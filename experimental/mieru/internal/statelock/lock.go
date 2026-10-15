package statelock

import (
	"fmt"
	"os"
)

// Acquire holds an exclusive lock until Close or process exit. The lock file
// must remain in place: unlinking it would let another process lock a new inode.
func Acquire(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open state lock (legacy lock directories need operator review): %w", err)
	}
	if err := tryLock(file); err != nil {
		file.Close()
		return nil, fmt.Errorf("acquire state lock; another adapter may be running: %w", err)
	}
	return file, nil
}
