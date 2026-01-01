package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/eliasvasylenko/secret-agent/internal/roles"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/eliasvasylenko/secret-agent/internal/store"
)

type Server struct {
	socket      string
	secretStore store.Secrets
	permissions *Permissions
}

func New(socket string, secretStore store.Secrets, permissions *Permissions) *Server {
	return &Server{socket, secretStore, permissions}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	handle := func(pattern string, subject roles.Subject, action roles.Action, handle func(w http.ResponseWriter, r *http.Request) (any, int, error)) {
		mux.Handle(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			connection := r.Context().Value(connectionKey{}).(net.Conn)
			identity, err := s.permissions.Claims.ClaimRoles(r, connection)
			if err != nil {
				writeError(w, NewErrorResponse(http.StatusUnauthorized, err))
				return
			}

			err = s.permissions.Roles.AssertPermission(identity, roles.Permissions{subject: action})
			if err != nil {
				writeError(w, NewErrorResponse(http.StatusForbidden, err))
				return
			}

			result, code, err := handle(w, r)
			if err != nil {
				writeError(w, err)
				return
			}

			writeResult(w, result, code)
		}))
	}

	handle("GET /secrets", roles.Secrets, roles.List,
		func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			secs, err := s.secretStore.List(r.Context())
			if err != nil {
				return nil, 0, NewErrorResponse(http.StatusBadRequest, err)
			}
			return ItemsResponse[secrets.Secrets]{secs}, http.StatusOK, nil
		})

	handle("GET /secrets/{secretId}", roles.Secrets, roles.Read,
		func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			secretId := r.PathValue("secretId")
			secret, err := s.secretStore.Get(r.Context(), secretId)
			if err != nil {
				return nil, 0, NewErrorResponse(http.StatusBadRequest, err)
			}
			return secret, http.StatusOK, nil
		})

	handle("GET /secrets/{secretId}/instances", roles.Instances, roles.Read,
		func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			secretId := r.PathValue("secretId")
			instances := s.secretStore.Instances(secretId)
			from, to, err := parseRange(*r.URL)
			insts, err := instances.List(r.Context(), from, to)
			if err != nil {
				return nil, 0, err
			}
			return ItemsResponse[secrets.Instances]{insts}, http.StatusOK, nil
		})

	handle("POST /secrets/{secretId}/instances", roles.Instances, roles.Write,
		func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			secretId := r.PathValue("secretId")
			instances := s.secretStore.Instances(secretId)
			var operation OperationCreate
			err := readBody(r, &operation)
			if err != nil {
				return nil, 0, err
			}
			parameters := secrets.OperationParameters{
				Env:       operation.Env,
				Forced:    operation.Forced,
				Reason:    operation.Reason,
				StartedBy: operation.StartedBy,
			}
			instance, err := instances.Create(r.Context(), parameters)
			if err != nil {
				return nil, 0, err
			}
			return instance, http.StatusOK, nil
		})

	handle("GET /secrets/{secretId}/instances/{instanceId}", roles.Instances, roles.Read,
		func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			secretId := r.PathValue("secretId")
			instanceId := r.PathValue("instanceId")
			instances := s.secretStore.Instances(secretId)
			instance, err := instances.Get(r.Context(), instanceId)
			if err != nil {
				return nil, 0, err
			}
			return instance, http.StatusOK, nil
		})

	handle("GET /secrets/{secretId}/instances/{instanceId}/operations", roles.Instances, roles.Read,
		func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			secretId := r.PathValue("secretId")
			instanceId := r.PathValue("instanceId")
			from, to, err := parseRange(*r.URL)
			instances := s.secretStore.Instances(secretId)
			operations, err := instances.History(r.Context(), instanceId, int(from), int(to))
			if err != nil {
				return nil, 0, err
			}
			return operations, http.StatusOK, nil
		})

	handle("POST /secrets/{secretId}/instances/{instanceId}/operations", roles.Instances, roles.Write,
		func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			secretId := r.PathValue("secretId")
			instanceId := r.PathValue("instanceId")
			var operation OperationCreate
			err := readBody(r, &operation)
			if err != nil {
				return nil, 0, err
			}

			parameters := secrets.OperationParameters{
				Env:       operation.Env,
				Forced:    operation.Forced,
				Reason:    operation.Reason,
				StartedBy: operation.StartedBy,
			}
			instances := s.secretStore.Instances(secretId)
			var instance *secrets.Instance
			switch operation.Name {
			case secrets.Activate:
				instance, err = instances.Activate(r.Context(), instanceId, parameters)
			case secrets.Deactivate:
				instance, err = instances.Deactivate(r.Context(), instanceId, parameters)
			case secrets.Destroy:
				instance, err = instances.Destroy(r.Context(), instanceId, parameters)
			case secrets.Test:
				instance, err = instances.Test(r.Context(), instanceId, parameters)
			default:
				return nil, 0, NewErrorResponse(http.StatusBadRequest, fmt.Errorf("Cannot post operation %s", operation.Name))
			}
			if err != nil {
				return nil, 0, err
			}
			return instance, http.StatusOK, nil
		})

	return mux
}

type connectionKey struct{}

func (s *Server) Serve() error {
	var listener net.Listener
	var err error
	if s.socket != "" {
		// socket option given for manual execution

		// resolve socket
		var addr *net.UnixAddr
		addr, err = net.ResolveUnixAddr("unix", s.socket)
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

	srv := &http.Server{
		Handler: s.Handler(),
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

func readBody(r *http.Request, v any) error {
	bytes, err := io.ReadAll(r.Body)
	if err == nil {
		err = json.Unmarshal(bytes, v)
	}
	if err != nil {
		return NewErrorResponse(http.StatusBadRequest, err)
	}
	return nil
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
	if !errors.As(err, &response) {
		response = NewErrorResponse(
			http.StatusInternalServerError,
			err,
		)
	}
	return writeResult(w, response, response.HttpError.Code)
}

func parseRange(url url.URL) (int, int, error) {
	from, err := parseInt(url, "from", 32)
	if err != nil {
		return from, 0, err
	}
	to, err := parseInt(url, "to", 32)
	return from, to, err
}

func parseInt(url url.URL, name string, defaultValue int) (int, error) {
	numString := url.Query().Get(name)
	if numString == "" {
		return defaultValue, nil
	}
	num, err := strconv.ParseInt(numString, 10, 32)
	if err != nil {
		return 0, NewErrorResponse(http.StatusBadRequest, fmt.Errorf("failed to parse '%s' - %w", name, err))
	}
	return int(num), nil
}
