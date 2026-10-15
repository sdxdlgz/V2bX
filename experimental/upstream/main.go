package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type Agent struct {
	config      Config
	relay       *Relay
	active      *Core
	revision    int
	lastPanel   time.Time
	nextRefresh time.Time
	report      Report
	digest      [32]byte
}

func (a *Agent) revoke() {
	a.relay.set("", true)
	if a.active != nil {
		a.active.stop()
		a.active = nil
	}
	a.revision = 0
	a.nextRefresh = time.Time{}
}

func (a *Agent) cycle(ctx context.Context) {
	s, err := snapshot(ctx, a.config)
	if err != nil {
		if errors.Is(err, errRevoked) || time.Since(a.lastPanel) > leaseTimeout {
			a.revoke()
		}
		log.Print("panel_unavailable")
		return
	}
	a.lastPanel = time.Now()
	if !s.Enabled {
		a.revoke()
		a.report = Report{Revision: s.Revision, Status: "disabled"}
		_, _ = panelRequest(ctx, a.config, "report", a.report)
		return
	}
	if a.active != nil && !a.active.alive() {
		a.revoke()
		a.nextRefresh = time.Time{}
	}
	if s.Revision != a.report.Revision || !time.Now().Before(a.nextRefresh) {
		a.update(ctx, s)
	}
	_, _ = panelRequest(ctx, a.config, "report", a.report)
}

func (a *Agent) update(ctx context.Context, s Snapshot) {
	a.report = Report{Revision: s.Revision, Status: "error"}
	if a.active != nil {
		revision := a.revision
		a.report.AppliedRevision = &revision
		a.report.Protocol = a.active.protocol
	}
	a.nextRefresh = time.Now().Add(30 * time.Second)
	source, err := fetchSource(ctx, a.config, s.Source)
	if err != nil {
		a.report.ErrorCode = "source_fetch"
		return
	}
	digest := sha256.Sum256(append(append([]byte{}, source...), []byte("\x00"+s.Selector)...))
	if a.active != nil && a.active.alive() && digest == a.digest {
		a.revision = s.Revision
		revision := s.Revision
		a.report = Report{Revision: s.Revision, AppliedRevision: &revision, Status: "ready", Protocol: a.active.protocol}
		a.nextRefresh = time.Now().Add(time.Duration(s.RefreshInterval) * time.Second)
		return
	}
	core, err := startCore(ctx, a.config, source, s.Selector)
	if err != nil {
		a.report.ErrorCode = err.Error()
		return
	}
	// Recheck authorization after slow download/probe; do not activate a superseded edit.
	latest, err := snapshot(ctx, a.config)
	if err != nil || !latest.Enabled || latest.Revision != s.Revision {
		core.stop()
		a.report.ErrorCode = "panel_unavailable"
		if errors.Is(err, errRevoked) || (err == nil && !latest.Enabled) {
			a.revoke()
		}
		return
	}
	a.lastPanel = time.Now()
	old := a.active
	a.active = core
	a.digest = digest
	a.revision = s.Revision
	a.relay.set(core.address, false)
	if old != nil {
		old.stop()
	}
	revision := s.Revision
	a.report = Report{Revision: s.Revision, AppliedRevision: &revision, Status: "ready", Protocol: core.protocol}
	a.nextRefresh = time.Now().Add(time.Duration(s.RefreshInterval) * time.Second)
	log.Print("upstream_ready protocol=", core.protocol)
}

func run(ctx context.Context, c Config) error {
	if err := os.MkdirAll(c.StateDir, 0700); err != nil {
		return errors.New("cannot create state directory")
	}
	lock, err := acquireLock(c.StateDir)
	if err != nil {
		return errors.New("state directory is locked or unsupported")
	}
	defer lock.Close()
	if err = checkCore(ctx, c.Mihomo); err != nil {
		return err
	}
	// Crashed children are killed by Linux; their private temporary files are owned by this locked instance.
	entries, _ := os.ReadDir(c.StateDir)
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "core-") {
			_ = os.RemoveAll(filepath.Join(c.StateDir, entry.Name()))
		}
	}
	relay, err := newRelay(c.Listen)
	if err != nil {
		return errors.New("cannot bind loopback listener")
	}
	defer relay.close()
	a := &Agent{config: c, relay: relay}
	defer a.revoke()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		a.cycle(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func main() {
	configPath := flag.String("config", "", "private gateway JSON configuration")
	flag.Parse()
	c, err := readConfig(*configPath)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err = run(ctx, c); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
