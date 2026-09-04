package policy

import (
	"math/rand"
	"testing"
)

func TestBanditExploresEveryArmFirst(t *testing.T) {
	actions := []Action{
		{Name: "a", Type: ActionBypassHeader},
		{Name: "b", Type: ActionBypassHeader},
		{Name: "c", Type: ActionBypassHeader},
	}
	b := NewBandit(actions, rand.New(rand.NewSource(1)))

	seen := map[string]bool{}
	for i := 0; i < len(actions); i++ {
		a := b.SelectAction()
		seen[a.Name] = true
		b.Reward(a, 0.0)
	}
	if len(seen) != len(actions) {
		t.Errorf("expected every arm explored once before exploitation, saw %v", seen)
	}
}

func TestBanditConvergesToBestArm(t *testing.T) {
	actions := []Action{
		{Name: "bad", Type: ActionBypassHeader},
		{Name: "good", Type: ActionBypassHeader},
	}
	b := NewBandit(actions, rand.New(rand.NewSource(42)))

	for i := 0; i < 200; i++ {
		a := b.SelectAction()
		if a.Name == "good" {
			b.Reward(a, 1.0)
		} else {
			b.Reward(a, 0.0)
		}
	}

	stats := b.Stats()
	if stats["good"] <= stats["bad"] {
		t.Errorf("bandit should favor the rewarding arm: good=%.2f bad=%.2f", stats["good"], stats["bad"])
	}
}

func TestRewardFromStatus(t *testing.T) {
	if RewardFromStatus(200) <= RewardFromStatus(403) {
		t.Error("200 should reward higher than 403")
	}
	if RewardFromStatus(429) >= 0 {
		t.Error("429 (rate limited) should be penalized")
	}
}

func TestPolicyEngineSlowdown(t *testing.T) {
	pe := NewPolicyEngine(rand.New(rand.NewSource(1)))
	host := "target.example"

	// Feed heavy blocking (403) beyond the min-sample threshold.
	for i := 0; i < 20; i++ {
		pe.RecordOutcome(host, 403, 12.0, "Cloudflare")
	}
	if !pe.ShouldSlowDown(host) {
		t.Error("expected slowdown after sustained blocking")
	}

	fresh := "clean.example"
	for i := 0; i < 20; i++ {
		pe.RecordOutcome(fresh, 200, 8.0, "")
	}
	if pe.ShouldSlowDown(fresh) {
		t.Error("healthy host should not trigger slowdown")
	}
}

func TestPolicyEnginePerHostBandit(t *testing.T) {
	pe := NewPolicyEngine(rand.New(rand.NewSource(1)))
	b1 := pe.GetBandit("a.example")
	b2 := pe.GetBandit("a.example")
	b3 := pe.GetBandit("b.example")
	if b1 != b2 {
		t.Error("same host should return the same bandit instance")
	}
	if b1 == b3 {
		t.Error("different hosts should get distinct bandits")
	}
}
