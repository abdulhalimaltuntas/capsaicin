package cluster

import (
	"testing"

	"github.com/capsaicin/scanner/internal/scanner"
)

func newTestMaster(words []string, chunkSize int) *Master {
	return NewMaster(":0", "https://target.example", words, []string{".php"}, chunkSize, ScanConfigParams{
		Threads: 10,
		Timeout: 10,
	})
}

func TestSplitAndEnqueueChunkCount(t *testing.T) {
	words := make([]string, 0, 25)
	for i := 0; i < 25; i++ {
		words = append(words, "w")
	}
	m := newTestMaster(words, 10)

	got := m.SplitAndEnqueue()
	if got != 3 { // 10 + 10 + 5
		t.Errorf("expected 3 chunks for 25 words @ size 10, got %d", got)
	}
	if m.RemainingChunks() != 3 {
		t.Errorf("expected 3 queued chunks, got %d", m.RemainingChunks())
	}
}

func TestGetNextChunkDrains(t *testing.T) {
	m := newTestMaster([]string{"a", "b", "c"}, 2)
	total := m.SplitAndEnqueue() // 2 chunks

	seen := 0
	for {
		chunk := m.GetNextChunk("agent-1")
		if chunk == nil {
			break
		}
		if chunk.TargetURL != "target.example" && chunk.TargetURL == "" {
			t.Error("chunk missing target URL")
		}
		seen++
	}
	if seen != total {
		t.Errorf("expected to drain %d chunks, drained %d", total, seen)
	}
	if m.GetNextChunk("agent-1") != nil {
		t.Error("expected nil once chunks exhausted")
	}
}

func TestRecordResultAndHeartbeat(t *testing.T) {
	m := newTestMaster([]string{"a"}, 1)

	m.RecordResult(scanner.Result{URL: "https://target.example/admin", StatusCode: 200})
	if got := m.GetResults(); len(got) != 1 {
		t.Fatalf("expected 1 recorded result, got %d", len(got))
	}

	m.RecordHeartbeat("agent-1", &AgentInfo{ID: "agent-1", Alive: true, Processed: 5})
	if m.ActiveAgentCount() != 1 {
		t.Errorf("expected 1 active agent, got %d", m.ActiveAgentCount())
	}

	// Second heartbeat updates stats without duplicating the agent.
	m.RecordHeartbeat("agent-1", &AgentInfo{ID: "agent-1", Alive: true, Processed: 12})
	agents := m.GetAgents()
	if len(agents) != 1 {
		t.Errorf("expected 1 agent after update, got %d", len(agents))
	}
	if agents["agent-1"].Processed != 12 {
		t.Errorf("expected processed=12 after heartbeat update, got %d", agents["agent-1"].Processed)
	}
}
