//go:build !linux

package main

import (
	"errors"
	"os"
	"os/exec"
)

func configureChild(cmd *exec.Cmd)         {}
func terminateChild(cmd *exec.Cmd) error   { return cmd.Process.Kill() }
func acquireLock(string) (*os.File, error) { return nil, errors.New("upstream service requires Linux") }
