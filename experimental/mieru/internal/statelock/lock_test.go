//go:build linux || windows

package statelock_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/sdxdlgz/V2bX/experimental/mieru/internal/statelock"
)

func TestLockHelper(t *testing.T) {
	path := os.Getenv("MIERU_TEST_LOCK_PATH")
	if path == "" {
		return
	}
	lock, err := statelock.Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	fmt.Println("locked")
	io.Copy(io.Discard, os.Stdin)
}

func TestExclusiveLockSurvivesProcessRestart(t *testing.T) {
	for _, crash := range []bool{false, true} {
		t.Run(fmt.Sprintf("crash=%v", crash), func(t *testing.T) {
			checkRestart(t, crash)
		})
	}
}

func checkRestart(t *testing.T, crash bool) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json.lock")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLockHelper$")
	child.Env = append(os.Environ(), "MIERU_TEST_LOCK_PATH="+path)
	child.Stderr = os.Stderr
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { child.Process.Kill(); child.Wait() }()
	line, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || line != "locked\n" {
		t.Fatalf("child failed to acquire lock: %q, %v", line, err)
	}
	if second, err := statelock.Acquire(path); err == nil {
		second.Close()
		t.Fatal("two processes acquired the same state lock")
	}
	if crash {
		if err := child.Process.Kill(); err != nil {
			t.Fatal(err)
		}
	} else {
		input.Close()
	}
	if err := child.Wait(); !crash && err != nil {
		t.Fatal(err)
	}
	lock, err := statelock.Acquire(path)
	if err != nil {
		t.Fatalf("restart could not recover existing lock file: %v", err)
	}
	lock.Close()
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
		t.Fatal("lock file must remain present after release")
	}
}

func TestLegacyDirectoryAndMissingParentFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json.lock")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{path, filepath.Join(path, "missing", "lock")} {
		if lock, err := statelock.Acquire(candidate); err == nil {
			lock.Close()
			t.Fatalf("unsafe or invalid lock path accepted: %s", candidate)
		}
	}
	if info, err := os.Stat(path); err != nil || !info.IsDir() {
		t.Fatal("legacy directory lock was modified")
	}
}
