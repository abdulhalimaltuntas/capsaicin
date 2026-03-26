package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/capsaicin/scanner/internal/cluster"
	"github.com/capsaicin/scanner/internal/config"
)

func main() {
	fmt.Println("🌶  Capsaicin Agent v3.0 — Remote Scanning Worker")
	fmt.Println("─────────────────────────────────────────────────")

	masterAddr := os.Getenv("CAPSAICIN_MASTER")
	if masterAddr == "" {
		masterAddr = "localhost:9090"
	}

	agentID := os.Getenv("CAPSAICIN_AGENT_ID")

	cfg := config.Config{
		Threads:       10,
		Timeout:       10,
		RetryAttempts: 2,
		MaxResponseMB: 10,
		RateLimit:     50,
		SafeMode:      false,
		JitterProfile: "moderate",
	}

	agent := cluster.NewAgent(agentID, masterAddr, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Printf("[AGENT] Received signal %s, shutting down...", sig)
		cancel()
	}()

	log.Printf("[AGENT] Agent %s connecting to master at %s", agent.ID, masterAddr)
	log.Printf("[AGENT] Waiting for gRPC connection... (standalone mode: connect via Master.RunPullLoop)")

	// In standalone mode, the agent would connect via gRPC.
	// For local testing, you can use RunPullLoop with a direct Master reference.
	fmt.Println("Agent ready. Set CAPSAICIN_MASTER to connect to a remote master.")

	// Block until signal.
	<-ctx.Done()
	log.Println("[AGENT] Agent shutdown complete")
}
