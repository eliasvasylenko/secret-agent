package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/store"
)

type Server struct {
	config     ServerConfig
	controller *Controller
}

type ServerConfig struct {
	Socket        string
	RequestLimit  uint32
	RequestWindow time.Duration
}

func New(config ServerConfig, secretStore store.Secrets, permissions *Permissions) *Server {
	limiter := NewLimiter(config.RequestLimit, config.RequestWindow)
	return &Server{
		config:     config,
		controller: NewController(secretStore, limiter, permissions),
	}
}

// Context key for passing the underlying connection into the handler
type connectionKey struct{}

func (s *Server) Serve() error {
	var listener net.Listener
	var err error
	if s.config.Socket != "" {
		// socket option given for manual execution

		// resolve socket
		var addr *net.UnixAddr
		addr, err = net.ResolveUnixAddr("unix", s.config.Socket)
		if err != nil {
			return err
		}

		// listen on socket
		listener, err = net.ListenUnix("unix", addr)

	} else if os.Getenv("LISTEN_PID") == strconv.Itoa(os.Getpid()) {
		// started as a systemd service

		// open file descriptor
		f := os.NewFile(3, "socket")

		// listen on FD
		listener, err = net.FileListener(f)

	} else {
		return fmt.Errorf("No server socket")
	}

	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	s.controller.buildHandler(mux.Handle)
	srv := &http.Server{
		Handler: mux,
		ConnContext: func(ctx context.Context, connection net.Conn) context.Context {
			return context.WithValue(ctx, connectionKey{}, connection)
		},
	}

	// serve http over socket
	if err := srv.Serve(listener); err != nil {
		return err
	}
	return nil
}
