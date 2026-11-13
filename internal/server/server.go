package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/auth"
	"github.com/eliasvasylenko/secret-agent/internal/backend"
)

type Server struct {
	config     ServerConfig
	controller *Controller
}

type ServerConfig struct {
	Socket        string
	RequestLimit  uint32
	RequestWindow time.Duration
	// PendingOperationTTL is how long an unstarted operation stays readable. Zero uses the default.
	PendingOperationTTL time.Duration
	// FinishedOperationTTL is how long a finished operation stays readable. Zero uses the default.
	FinishedOperationTTL time.Duration
}

func New(config ServerConfig, secretStore backend.Backend, policy *auth.Policy) *Server {
	limiter := NewLimiter(config.RequestLimit, config.RequestWindow)
	return &Server{
		config:     config,
		controller: NewController(secretStore, policy, limiter, config.PendingOperationTTL, config.FinishedOperationTTL),
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
