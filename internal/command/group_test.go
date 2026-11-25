package command

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestGroupFiles_sameFileSharesAttach(t *testing.T) {
	read, out, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = read.Close() })
	dupfd, err := syscall.Dup(int(out.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	same := os.NewFile(uintptr(dupfd), out.Name())
	t.Cleanup(func() { _ = same.Close() })

	groups, err := GroupFiles(Files{Fds: []*os.File{nil, out, same}, Tty: NoTty})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want one shared output and no invented stdin", len(groups))
	}
	shared := groups[0]
	if !hasFds(shared.Fds, 1, 2) {
		t.Fatalf("shared fds = %v", shared.Fds)
	}
	if shared.Mode != Write {
		t.Fatalf("shared mode = %s, want w", shared.Mode)
	}
	if shared.File != out && shared.File != same {
		t.Fatal("shared output is not written once")
	}
}

func TestGroupFiles_dupSeparatedByAnotherFile(t *testing.T) {
	read, out, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = read.Close() })
	dupfd, err := syscall.Dup(int(out.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	same := os.NewFile(uintptr(dupfd), out.Name())
	t.Cleanup(func() { _ = same.Close() })

	path := filepath.Join(t.TempDir(), "other")
	created, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}
	other, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })

	groups, err := GroupFiles(Files{Fds: []*os.File{out, other, same}, Tty: NoTty})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want the dup together and the other file alone", len(groups))
	}
	var dup, alone *FileGroup
	for i := range groups {
		switch len(groups[i].Fds) {
		case 2:
			dup = &groups[i]
		case 1:
			alone = &groups[i]
		}
	}
	if dup == nil || alone == nil {
		t.Fatalf("groups = %+v", groups)
	}
	if dup.Mode != Write || !hasFds(dup.Fds, 0, 2) {
		t.Fatalf("dup group = %+v, want write fds 0 and 2", dup)
	}
	if alone.Mode != Read || alone.Fds[0] != 1 {
		t.Fatalf("other group = %+v, want read fd 1", alone)
	}
}

func TestGroupFiles_twoOpensAreSeparate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	created, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}
	first, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	second, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })

	groups, err := GroupFiles(Files{Fds: []*os.File{first, second}, Tty: NoTty})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want two opens", len(groups))
	}
}

func TestGroupFiles_readWriteFileIsNotAStream(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "rw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	_, err = GroupFiles(Files{Fds: []*os.File{f}, Tty: NoTty})
	if err == nil || !strings.Contains(err.Error(), "read-write file cannot be attached") {
		t.Fatalf("GroupFiles error = %v", err)
	}
}

func TestGroupFiles_ttyIndexOnFirstDescriptor(t *testing.T) {
	term := testPtySlave(t)
	groups, err := GroupFiles(Files{Fds: []*os.File{term}, Tty: 0})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want one", len(groups))
	}
	if groups[0].Mode != Ctty || len(groups[0].Fds) != 1 || groups[0].Fds[0] != 0 {
		t.Fatalf("group = %+v, want ctty fd 0", groups[0])
	}
}

func TestGroupFiles_ttyIndexPromotesGroup(t *testing.T) {
	term := testPtySlave(t)
	dupfd, err := syscall.Dup(int(term.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	same := os.NewFile(uintptr(dupfd), term.Name())
	t.Cleanup(func() { _ = same.Close() })

	groups, err := GroupFiles(Files{Fds: []*os.File{term, same}, Tty: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want one", len(groups))
	}
	group := groups[0]
	if !hasFds(group.Fds, 0, 1) {
		t.Fatalf("fds = %v, want 0 and 1", group.Fds)
	}
	if group.Mode != Ctty {
		t.Fatalf("mode = %s, want ctty", group.Mode)
	}
}

func TestFileGroups_Files(t *testing.T) {
	term := testPtySlave(t)
	read, out, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = read.Close() })
	t.Cleanup(func() { _ = out.Close() })

	files := FileGroups{
		{Fds: []int{0}, Mode: Read, File: read},
		{Fds: []int{1, 2}, Mode: Ctty, File: term},
	}.Files()
	if files.Tty != 1 {
		t.Fatalf("Tty = %d, want 1", files.Tty)
	}
	if files.Fds[0] != read || files.Fds[1] != term || files.Fds[2] != term {
		t.Fatalf("Fds = %v", files.Fds)
	}
}

func hasFds(fds []int, want ...int) bool {
	if len(fds) != len(want) {
		return false
	}
	seen := map[int]bool{}
	for _, fd := range fds {
		seen[fd] = true
	}
	for _, fd := range want {
		if !seen[fd] {
			return false
		}
	}
	return true
}

func testPtySlave(t *testing.T) *os.File {
	t.Helper()
	slave, master, err := OpenPty()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = master.Close()
		_ = slave.Close()
	})
	return slave
}
