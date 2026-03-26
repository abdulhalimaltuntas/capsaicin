package cluster

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/capsaicin/scanner/internal/config"
	"github.com/capsaicin/scanner/internal/scanner"
)

// Agent is a remote worker that connects to a Master, pulls scan chunks,
// executes them using the local scan engine, and reports results back.
type Agent struct {
	ID         string
	MasterAddr string
	Config     config.Config

	// Communication channels
	results chan scanner.Result
	status  *AgentInfo
}

// NewAgent creates a new scanning agent.
func NewAgent(id, masterAddr string, cfg config.Config) *Agent {
	hostname, _ := os.Hostname()
	if id == "" {
		id = fmt.Sprintf("agent-%s-%d", hostname, time.Now().UnixNano()%10000)
	}

	return &Agent{
		ID:         id,
		MasterAddr: masterAddr,
		Config:     cfg,
		results:    make(chan scanner.Result, 1000),
		status: &AgentInfo{
			ID:    id,
			Alive: true,
		},
	}
}

// ExecuteChunk processes a single scan chunk using the local scanner engine.
// This reuses the existing battle-tested scanner.Engine internally.
func (a *Agent) ExecuteChunk(ctx context.Context, chunk *ScanChunk) ([]scanner.Result, error) {
	// Override config with chunk-specific settings.
	cfg := a.Config
	cfg.Wordlist = "" // Words come from chunk, not file
	cfg.Extensions = chunk.Extensions

	if chunk.Config.Threads > 0 {
		cfg.Threads = chunk.Config.Threads
	}
	if chunk.Config.RateLimit > 0 {
		cfg.RateLimit = chunk.Config.RateLimit
	}
	if chunk.Config.Timeout > 0 {
		cfg.Timeout = chunk.Config.Timeout
	}
	cfg.SafeMode = chunk.Config.SafeMode
	if chunk.Config.JitterProfile != "" {
		cfg.JitterProfile = chunk.Config.JitterProfile
	}
	if chunk.Config.TLSImpersonate != "" {
		cfg.TLSImpersonate = chunk.Config.TLSImpersonate
	}
	cfg.ForceHTTP2 = chunk.Config.ForceHTTP2

	for k, v := range chunk.Config.CustomHeaders {
		if cfg.CustomHeaders == nil {
			cfg.CustomHeaders = make(map[string]string)
		}
		cfg.CustomHeaders[k] = v
	}

	engine, err := scanner.NewEngine(cfg)
	if err != nil {
		return nil, fmt.Errorf("agent %s: engine init failed: %w", a.ID, err)
	}

	targets := []string{chunk.TargetURL}

	results, stats, err := engine.RunContext(ctx, targets)
	if err != nil {
		log.Printf("[AGENT %s] Chunk %s failed: %v", a.ID, chunk.ChunkID, err)
		return results, err
	}

	// Update agent status.
	if stats != nil {
		a.status.Processed = stats.GetProcessed()
		a.status.Found = stats.GetFound()
		a.status.Errors = stats.GetErrors()
		a.status.LastHeartbeat = time.Now()
	}

	log.Printf("[AGENT %s] Chunk %s completed: %d results", a.ID, chunk.ChunkID, len(results))
	return results, nil
}

// RunPullLoop connects to the master and continuously pulls chunks until none remain.
// This is the main event loop for a standalone agent deployment.
func (a *Agent) RunPullLoop(ctx context.Context, master *Master) error {
	log.Printf("[AGENT %s] Starting pull loop against master", a.ID)

	for {
		select {
		case <-ctx.Done():
			log.Printf("[AGENT %s] Context cancelled, shutting down", a.ID)
			return ctx.Err()
		default:
		}

		chunk := master.GetNextChunk(a.ID)
		if chunk == nil {
			log.Printf("[AGENT %s] No more chunks, finishing", a.ID)
			return nil
		}

		results, err := a.ExecuteChunk(ctx, chunk)
		if err != nil {
			log.Printf("[AGENT %s] Error processing chunk %s: %v", a.ID, chunk.ChunkID, err)
			continue
		}

		// Report results back to master.
		for _, r := range results {
			master.RecordResult(r)
		}

		// Send heartbeat.
		master.RecordHeartbeat(a.ID, a.status)
	}
}

// GetStatus returns the current agent health status.
func (a *Agent) GetStatus() *AgentInfo {
	return a.status
}
