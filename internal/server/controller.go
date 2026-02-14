package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/auth"
	"github.com/eliasvasylenko/secret-agent/internal/store"
)

type Controller struct {
	config      ServerConfig
	service     *Service
	permissions *Permissions
	limiter     *Limiter
}

type ServerConfig struct {
	Socket        string
	RequestLimit  uint32
	RequestWindow time.Duration
}

func NewController(config ServerConfig, secretStore store.Secrets, permissions *Permissions) *Controller {
	limiter := NewLimiter(config.RequestLimit, config.RequestWindow)
	return &Controller{
		config:      config,
		service:     &Service{secretStore},
		permissions: permissions,
		limiter:     limiter,
	}
}

// Context key for passing the underlying connection into the handler
type connectionKey struct{}

func (c *Controller) Serve() error {
	var listener net.Listener
	var err error
	if c.config.Socket != "" {
		// socket option given for manual execution

		// resolve socket
		var addr *net.UnixAddr
		addr, err = net.ResolveUnixAddr("unix", c.config.Socket)
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
	c.buildHandler(mux.Handle)
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

func (c *Controller) buildHandler(registerHandler func(pattern string, handler http.Handler)) {
	registerHandler("GET /secrets", c.buildHandlerFunc(
		auth.Permissions{auth.Secrets: auth.List},
		c.service.listSecrets,
	))
	registerHandler("GET /secrets/{secretId}", c.buildHandlerFunc(
		auth.Permissions{auth.Secrets: auth.Read},
		c.service.getSecret,
	))
	registerHandler("GET /secrets/{secretId}/instances", c.buildHandlerFunc(
		auth.Permissions{auth.Instances: auth.Read},
		c.service.listInstances,
	))
	registerHandler("POST /secrets/{secretId}/instances", c.buildHandlerFunc(
		auth.Permissions{auth.Instances: auth.Write},
		c.service.createInstance,
	))
	registerHandler("GET /secrets/{secretId}/instances/{instanceId}", c.buildHandlerFunc(
		auth.Permissions{auth.Instances: auth.Read},
		c.service.getInstance,
	))

	registerHandler("GET /secrets/{secretId}/instances/{instanceId}/operations", c.buildHandlerFunc(
		auth.Permissions{auth.Instances: auth.Read},
		c.service.getOperations,
	))

	registerHandler("POST /secrets/{secretId}/instances/{instanceId}/operations", c.buildHandlerFunc(
		auth.Permissions{auth.Secrets: auth.Write, auth.Instances: auth.Write},
		c.service.createOperation,
	))
}

func (c *Controller) buildHandlerFunc(permissions auth.Permissions, handle func(w http.ResponseWriter, r *http.Request) (any, int, error)) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection := r.Context().Value(connectionKey{}).(net.Conn)
		identity, err := c.permissions.Claims.ClaimIdentity(r, connection)
		if err != nil {
			writeError(w, NewErrorResponse(http.StatusUnauthorized, err))
			return
		}

		err = c.permissions.Roles.AssertPermission(identity.Roles, permissions)
		if err != nil {
			writeError(w, NewErrorResponse(http.StatusForbidden, err))
			return
		}

		err = c.limiter.Allow(identity.Principal)
		if err != nil {
			writeError(w, err)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), identityKey{}, identity))

		result, code, err := handle(w, r)
		if err != nil {
			writeError(w, err)
			return
		}

		writeResult(w, result, code)
	})
}

func writeResult(w http.ResponseWriter, value any, statusCode int) error {
	w.WriteHeader(statusCode)

	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(value)
	if err != nil {
		return err
	}

	return nil
}

func writeError(w http.ResponseWriter, err error) error {
	var response *ErrorResponse
	if errors.As(err, &response) {
		w.Header().Add("", "")
	} else {
		response = NewErrorResponse(
			http.StatusInternalServerError,
			err,
		)
	}
	return writeResult(w, response, response.HttpError.Code)
}
