//go:build linux

package command

import (
	"errors"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

const drainTimeout = 250 * time.Millisecond

// Broker copies between the caller's terminals and PTY slaves that a
// backend may be given. Close restores any terminal it changed.
type Broker struct {
	Groups FileGroups

	once  sync.Once
	state *brokerState
}

func (b *Broker) Files() Files {
	return b.Groups.Files()
}

// Close restores terminals, hangs up leftover holders of the slaves, and
// is safe to call more than once.
func (b *Broker) Close() {
	if b == nil {
		return
	}
	b.once.Do(func() {
		if b.state != nil {
			b.state.shutdown()
		}
	})
}

// bridge is a file the script holds and the end the CLI copies on: a
// PTY slave and its master, or one pipe end and the other.
type bridge struct {
	script, here *os.File
}

type brokerState struct {
	bridges  []*bridge
	rawFile  *os.File
	restore  func()
	signalCh chan os.Signal
	stop     chan struct{}
	wg       sync.WaitGroup
	output   sync.WaitGroup
}

// OpenBroker gives the controlling terminal, when it is among fds, one
// PTY. Any other terminal becomes a pipe: stdin is the read end, and
// every other descriptor is the write end. A terminal that is both is
// split into those two streams. The script never receives a terminal
// the CLI did not create. A read-write non-terminal keeps an empty
// Mode. Index is the descriptor number; nil slots are skipped.
func OpenBroker(fds []*os.File) (*Broker, error) {
	s := &brokerState{stop: make(chan struct{})}
	b := &Broker{state: s}
	groups, err := s.wrap(fds)
	if err != nil {
		b.Close()
		return nil, err
	}
	b.Groups = groups
	return b, nil
}

func (s *brokerState) wrap(fds []*os.File) (FileGroups, error) {
	groups, err := groupByOpenFile(fds)
	if err != nil {
		return nil, err
	}
	var out FileGroups
	for _, group := range groups {
		mode, err := LocalMode(group.File)
		if errors.Is(err, errReadWriteFile) {
			out = append(out, group)
			continue
		}
		if err != nil {
			return nil, err
		}
		if !mode.Terminal() {
			group.Mode = mode
			out = append(out, group)
			continue
		}
		if !ControllingTerminal(group.File) {
			piped, err := s.pipeTerminal(group)
			if err != nil {
				return nil, err
			}
			out = append(out, piped...)
			continue
		}
		wrapped, err := s.wrapControlling(group)
		if err != nil {
			return nil, err
		}
		out = append(out, wrapped)
	}
	return out, nil
}

func (s *brokerState) wrapControlling(group FileGroup) (FileGroup, error) {
	slave, master, err := OpenPty()
	if err != nil {
		return FileGroup{}, err
	}
	p := &bridge{script: slave, here: master}
	s.bridges = append(s.bridges, p)
	_ = pty.InheritSize(group.File, master)
	if err := s.raw(group.File); err != nil {
		return FileGroup{}, err
	}
	s.watchSignals(group.File, master)
	s.forward(p, group.File)
	return FileGroup{Fds: group.Fds, Mode: Ctty, File: slave}, nil
}

// pipeTerminal replaces a terminal that is not the controlling terminal.
// Stdin is a read pipe; every other descriptor is a write pipe. One open
// file that is both becomes two streams.
func (s *brokerState) pipeTerminal(group FileGroup) (FileGroups, error) {
	var reads, writes []int
	for _, fd := range group.Fds {
		if fd == 0 {
			reads = append(reads, fd)
		} else {
			writes = append(writes, fd)
		}
	}
	var out FileGroups
	if len(reads) > 0 {
		g, err := s.pipe(reads, group.File, Read)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	if len(writes) > 0 {
		g, err := s.pipe(writes, group.File, Write)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

func (s *brokerState) pipe(fds []int, terminal *os.File, mode FileMode) (FileGroup, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return FileGroup{}, err
	}
	p := &bridge{}
	s.bridges = append(s.bridges, p)
	if mode == Read {
		p.script, p.here = r, w
		s.copy(&s.wg, w, terminal)
	} else {
		p.script, p.here = w, r
		s.copy(&s.output, terminal, r)
	}
	return FileGroup{Fds: fds, Mode: mode, File: p.script}, nil
}

func (s *brokerState) raw(f *os.File) error {
	restore, err := setRaw(f)
	if err != nil {
		return err
	}
	s.rawFile = f
	s.restore = restore
	return nil
}

func (s *brokerState) forward(p *bridge, src *os.File) {
	s.copy(&s.wg, p.here, src)
	s.copy(&s.output, src, p.here)
}

func (s *brokerState) copy(wg *sync.WaitGroup, dst, src *os.File) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		pollCopy(dst, src, s.stop)
	}()
}

func (s *brokerState) watchSignals(src, master *os.File) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH, syscall.SIGTSTP)
	s.signalCh = ch
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			select {
			case sig := <-ch:
				if sig == syscall.SIGWINCH {
					_ = pty.InheritSize(src, master)
					continue
				}
				s.restore()
				_ = unix.Kill(unix.Getpid(), unix.SIGSTOP)
				if restore, err := setRaw(s.rawFile); err == nil {
					s.restore = restore
				}
			case <-s.stop:
				return
			}
		}
	}()
}

func (s *brokerState) shutdown() {
	if s.signalCh != nil {
		signal.Stop(s.signalCh)
	}
	// With our script ends closed, output copies finish at EOF (EIO on a
	// master). A leftover still holding one is cut off after drainTimeout.
	for _, p := range s.bridges {
		_ = p.script.Close()
	}
	waitTimeout(&s.output, drainTimeout)
	close(s.stop)
	s.wg.Wait()
	s.output.Wait()
	if s.restore != nil {
		s.restore()
	}
	for _, p := range s.bridges {
		_ = p.here.Close()
	}
}

func waitTimeout(wg *sync.WaitGroup, d time.Duration) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
	}
}

func pollCopy(dst, src *os.File, stop <-chan struct{}) {
	buf := make([]byte, 8192)
	srcFd := int(src.Fd())
	fds := []unix.PollFd{{Fd: int32(srcFd), Events: unix.POLLIN}}
	for {
		select {
		case <-stop:
			return
		default:
		}
		n, err := unix.Poll(fds, 100)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return
		}
		if n == 0 {
			continue
		}
		if fds[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) == 0 {
			continue
		}
		nr, err := unix.Read(srcFd, buf)
		if nr > 0 {
			if _, werr := dst.Write(buf[:nr]); werr != nil {
				return
			}
		}
		if nr == 0 || err != nil {
			return
		}
	}
}
