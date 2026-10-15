package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sdxdlgz/V2bX/experimental/mieru/agent"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	configPath := flag.String("config", "", "private JSON configuration file")
	flag.Parse()
	var config struct {
		PanelURL  string `json:"panel_url"`
		Token     string `json:"token"`
		NodeID    int    `json:"node_id"`
		StateFile string `json:"state_file"`
	}
	raw, err := os.ReadFile(*configPath)
	if err != nil {
		return fmt.Errorf("read private configuration: %w", err)
	}
	if json.Unmarshal(raw, &config) != nil || config.StateFile == "" {
		return fmt.Errorf("invalid configuration")
	}
	if err = os.MkdirAll(filepath.Dir(config.StateFile), 0700); err != nil {
		return err
	}
	// A stale lock after a crash requires operator review; never run two writers.
	lock := config.StateFile + ".lock"
	if err = os.Mkdir(lock, 0700); err != nil {
		return fmt.Errorf("state is locked; check for another or crashed adapter")
	}
	defer os.Remove(lock)
	state, err := agent.LoadState(config.StateFile)
	if err != nil {
		return err
	}
	engine := &agent.Engine{Proxy: &agent.Runtime{}, State: state,
		API:  &agent.Panel{BaseURL: config.PanelURL, Token: config.Token, NodeID: config.NodeID},
		Save: func(s *agent.State) error { return agent.SaveState(config.StateFile, s) }}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	defer func() {
		closing, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if err := engine.Stop(closing); err != nil {
			log.Printf("shutdown: %v; counters retained locally", err)
		}
	}()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		step, done := context.WithTimeout(ctx, 15*time.Second)
		err := engine.Step(step)
		done()
		if err != nil {
			closing, finish := context.WithTimeout(context.Background(), 5*time.Second)
			stopErr := engine.Stop(closing)
			finish()
			log.Printf("sync: %v; proxy stopped", err)
			if stopErr != nil {
				log.Printf("pending traffic: %v", stopErr)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
