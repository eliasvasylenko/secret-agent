package sqlite

import (
	"errors"
	"os"
	"testing"
)

func TestTryLockInstance_removesFileOnUnlock(t *testing.T) {
	r := &Repository{lockDir: t.TempDir()}
	lock, held, err := r.tryLockInstance("inst")
	if err != nil || !held {
		t.Fatalf("tryLockInstance: held=%v err=%v", held, err)
	}
	if _, err := os.Stat(r.lockPath("inst")); err != nil {
		t.Fatalf("lock file missing while held: %v", err)
	}

	lock.Unlock()
	if _, err := os.Stat(r.lockPath("inst")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock file still present after Unlock: %v", err)
	}
}

func TestTryLockInstance_heldBlocksAndKeepsFile(t *testing.T) {
	r := &Repository{lockDir: t.TempDir()}
	heldLock, held, err := r.tryLockInstance("inst")
	if err != nil || !held {
		t.Fatalf("tryLockInstance: held=%v err=%v", held, err)
	}
	t.Cleanup(heldLock.Unlock)

	_, held, err = r.tryLockInstance("inst")
	if err != nil {
		t.Fatal(err)
	}
	if held {
		t.Fatal("second tryLockInstance held an already locked instance")
	}
	if _, err := os.Stat(r.lockPath("inst")); err != nil {
		t.Fatalf("lock file missing while first holder is live: %v", err)
	}
}
