package cluster

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/capsaicin/scanner/internal/scanner"
)

// Master coordinates distributed scanning across multiple remote agents.
// It splits the wordlist into chunks, assigns them to agents, and aggregates results.
type Master struct {
	mu       sync.RWMutex
	agents   map[string]*AgentInfo
	chunks   chan *ScanChunk
	results  []scanner.Result
	resultMu sync.Mutex

	// Configuration
	ListenAddr   string
	ChunkSize    int // Number of words per chunk
	TotalWords   []string
	TargetURL    string
	Extensions   []string
	ScanConfig   ScanConfigParams
}

// AgentInfo tracks the state of a connected remote agent.
type AgentInfo struct {
	ID            string
	LastHeartbeat time.Time
	Processed     int64
	Found         int64
	Errors        int64
	CurrentURL    string
	Alive         bool
}

// ScanConfigParams holds the configuration parameters sent to agents.
type ScanConfigParams struct {
	Threads        int
	RateLimit      int
	Timeout        int
	RetryAttempts  int
	SafeMode       bool
	JitterProfile  string
	TLSImpersonate string
	ForceHTTP2     bool
	CustomHeaders  map[string]string
}

// ScanChunk is a unit of work distributed to an agent.
type ScanChunk struct {
	ChunkID    string
	TargetURL  string
	Words      []string
	Extensions []string
	Depth      int
	Config     ScanConfigParams
}

// NewMaster creates a new master coordinator.
func NewMaster(listenAddr string, targetURL string, words []string, extensions []string, chunkSize int, cfg ScanConfigParams) *Master {
	return &Master{
		agents:     make(map[string]*AgentInfo),
		chunks:     make(chan *ScanChunk, 1000),
		ListenAddr: listenAddr,
		ChunkSize:  chunkSize,
		TotalWords: words,
		TargetURL:  targetURL,
		Extensions: extensions,
		ScanConfig: cfg,
	}
}

// SplitAndEnqueue divides the wordlist into chunks and pushes them to the queue.
func (m *Master) SplitAndEnqueue() int {
	totalChunks := 0
	for i := 0; i < len(m.TotalWords); i += m.ChunkSize {
		end := i + m.ChunkSize
		if end > len(m.TotalWords) {
			end = len(m.TotalWords)
		}

		chunk := &ScanChunk{
			ChunkID:    fmt.Sprintf("chunk-%d", totalChunks),
			TargetURL:  m.TargetURL,
			Words:      m.TotalWords[i:end],
			Extensions: m.Extensions,
			Depth:      1,
			Config:     m.ScanConfig,
		}

		m.chunks <- chunk
		totalChunks++
	}

	log.Printf("[MASTER] Enqueued %d chunks (%d words, chunk size %d)", totalChunks, len(m.TotalWords), m.ChunkSize)
	return totalChunks
}

// GetNextChunk returns the next available chunk for an agent.
// Returns nil if no more chunks are available.
func (m *Master) GetNextChunk(agentID string) *ScanChunk {
	select {
	case chunk := <-m.chunks:
		log.Printf("[MASTER] Assigned %s to agent %s", chunk.ChunkID, agentID)
		return chunk
	default:
		return nil // No more chunks
	}
}

// RecordResult stores a finding from a remote agent.
func (m *Master) RecordResult(result scanner.Result) {
	m.resultMu.Lock()
	defer m.resultMu.Unlock()
	m.results = append(m.results, result)
}

// RecordHeartbeat updates the health status of an agent.
func (m *Master) RecordHeartbeat(agentID string, status *AgentInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, ok := m.agents[agentID]
	if !ok {
		m.agents[agentID] = status
		log.Printf("[MASTER] New agent registered: %s", agentID)
		return
	}

	existing.LastHeartbeat = time.Now()
	existing.Processed = status.Processed
	existing.Found = status.Found
	existing.Errors = status.Errors
	existing.CurrentURL = status.CurrentURL
	existing.Alive = status.Alive
}

// GetResults returns all collected results.
func (m *Master) GetResults() []scanner.Result {
	m.resultMu.Lock()
	defer m.resultMu.Unlock()
	return append([]scanner.Result(nil), m.results...)
}

// GetAgents returns a snapshot of all connected agents.
func (m *Master) GetAgents() map[string]*AgentInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	snapshot := make(map[string]*AgentInfo, len(m.agents))
	for k, v := range m.agents {
		info := *v
		snapshot[k] = &info
	}
	return snapshot
}

// MonitorAgents periodically checks agent health and reassigns stuck chunks.
func (m *Master) MonitorAgents(ctx context.Context, staleTimeout time.Duration) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			for id, agent := range m.agents {
				if time.Since(agent.LastHeartbeat) > staleTimeout {
					log.Printf("[MASTER] Agent %s is stale (last heartbeat: %s ago)", id, time.Since(agent.LastHeartbeat))
					agent.Alive = false
				}
			}
			m.mu.Unlock()
		}
	}
}

// ActiveAgentCount returns the number of currently active agents.
func (m *Master) ActiveAgentCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, agent := range m.agents {
		if agent.Alive {
			count++
		}
	}
	return count
}

// RemainingChunks returns the number of unassigned chunks.
func (m *Master) RemainingChunks() int {
	return len(m.chunks)
}
