//go:build !linux && !windows

package statelock

import (
	"errors"
	"os"
)

func tryLock(*os.File) error {
	return errors.New("state locking is supported only on Linux and Windows")
}
