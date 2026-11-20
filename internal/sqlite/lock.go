package sqlite

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// instanceLock is an exclusive flock on one instance. The kernel drops it
// when this process dies. The file on disk is not the lock.
type instanceLock struct {
	file *os.File
	path string
}

func (r *Repository) lockPath(instanceId string) string {
	return filepath.Join(r.lockDir, filepath.Base(instanceId)+".lock")
}

func (r *Repository) tryLockInstance(instanceId string) (*instanceLock, bool, error) {
	if err := os.MkdirAll(r.lockDir, 0o700); err != nil {
		return nil, false, err
	}
	path := r.lockPath(instanceId)
	for {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, false, err
		}
		err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err != nil {
			_ = file.Close()
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				return nil, false, nil
			}
			return nil, false, err
		}
		var st unix.Stat_t
		if err := unix.Fstat(int(file.Fd()), &st); err != nil {
			_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
			_ = file.Close()
			return nil, false, err
		}
		if st.Nlink == 0 {
			// This lock file was deleted. Close it and try again.
			_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
			_ = file.Close()
			continue
		}
		return &instanceLock{file: file, path: path}, true, nil
	}
}

func (l *instanceLock) Unlock() {
	if l == nil || l.file == nil {
		return
	}
	_ = os.Remove(l.path)
	_ = unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	_ = l.file.Close()
	l.file = nil
}
