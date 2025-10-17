package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/eliasvasylenko/secret-agent/internal/secret"
	"github.com/eliasvasylenko/secret-agent/internal/store"
)

type Server struct {
	socket  string
	handler http.Handler
}

func New(socket string, secretStore store.Secrets, debug bool) (*Server, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /secrets", func(w http.ResponseWriter, r *http.Request) {
		secrets, err := secretStore.List(r.Context())
		if handleError(w, err, http.StatusBadRequest) {
			return
		}
		result := struct {
			Items []*secret.Secret `json:"items"`
		}{}
		for _, secret := range secrets {
			result.Items = append(result.Items, secret)
		}
		writeResult(w, http.StatusOK, result)
	})
	mux.HandleFunc("GET /secrets/{secretId}", func(w http.ResponseWriter, r *http.Request) {
		secretId := r.PathValue("secretId")
		secret, err := secretStore.Get(r.Context(), secretId)
		if !handleError(w, err, http.StatusBadRequest) {
			writeResult(w, http.StatusOK, secret)
		}
	})
	mux.HandleFunc("POST /secrets/{secretId}/instances", func(w http.ResponseWriter, r *http.Request) {
		secretId := r.PathValue("secretId")
		instances := secretStore.Instances(secretId)
		var operation OperationCreate
		if readBody(w, r, operation) {
			parameters := secret.OperationParameters{
				Env:       operation.Env,
				Forced:    operation.Forced,
				Reason:    operation.Reason,
				StartedBy: operation.StartedBy,
			}
			instance, err := instances.Create(r.Context(), parameters)
			if !handleError(w, err, http.StatusInternalServerError) {
				writeResult(w, http.StatusOK, instance)
			}
		}
	})
	mux.HandleFunc("GET /secrets/{secretId}/instances/{instanceId}", func(w http.ResponseWriter, r *http.Request) {
		secretId := r.PathValue("secretId")
		instanceId := r.PathValue("instanceId")
		instances := secretStore.Instances(secretId)
		instance, err := instances.Get(r.Context(), instanceId)
		if !handleError(w, err, http.StatusInternalServerError) {
			writeResult(w, http.StatusOK, instance)
		}
	})
	mux.HandleFunc("GET /secrets/{secretId}/instances/{instanceId}/operations", func(w http.ResponseWriter, r *http.Request) {
		secretId := r.PathValue("secretId")
		instanceId := r.PathValue("instanceId")
		instances := secretStore.Instances(secretId)
		operations, err := instances.History(r.Context(), instanceId, 0, 100)
		if !handleError(w, err, http.StatusInternalServerError) {
			writeResult(w, http.StatusOK, operations)
		}
	})
	mux.HandleFunc("POST /secrets/{secretId}/instances/{instanceId}/operations", func(w http.ResponseWriter, r *http.Request) {
		secretId := r.PathValue("secretId")
		instanceId := r.PathValue("instanceId")
		var operation OperationCreate
		if readBody(w, r, operation) {
			parameters := secret.OperationParameters{
				Env:       operation.Env,
				Forced:    operation.Forced,
				Reason:    operation.Reason,
				StartedBy: operation.StartedBy,
			}
			instances := secretStore.Instances(secretId)
			var instance *secret.Instance
			var err error
			switch operation.Name {
			case secret.Activate:
				instance, err = instances.Activate(r.Context(), instanceId, parameters)
			case secret.Deactivate:
				instance, err = instances.Deactivate(r.Context(), instanceId, parameters)
			case secret.Destroy:
				instance, err = instances.Destroy(r.Context(), instanceId, parameters)
			case secret.Test:
				instance, err = instances.Test(r.Context(), instanceId, parameters)
			default:
				writeError(w, http.StatusBadRequest, fmt.Errorf("Cannot post operation %s", operation.Name))
			}
			if !handleError(w, err, http.StatusInternalServerError) && instance != nil {
				writeResult(w, http.StatusOK, instance)
			}
		}
	})

	return &Server{
		handler: mux,
	}, nil
}

func readBody(w http.ResponseWriter, r *http.Request, v any) bool {
	bytes, err := io.ReadAll(r.Body)
	if err == nil {
		err = json.Unmarshal(bytes, v)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return false
	}
	return true
}

func (s *Server) Serve() error {
	// clear old socket
	if err := os.Remove(s.socket); err != nil {
		return err
	}
	// listen on socket
	unixListener, err := net.Listen("unix", s.socket)
	if err != nil {
		return err
	}
	// serve http over socket
	if err := http.Serve(unixListener, nil); err != nil {
		return err
	}
	return nil
}

func handleError(w http.ResponseWriter, err error, errorCode int) bool {
	errored := err != nil
	if errored {
		writeError(w, errorCode, err)
	}
	return errored
}

func writeResult(w http.ResponseWriter, successCode int, value any) error {
	w.WriteHeader(successCode)

	bytes, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = w.Write(bytes)
	if err != nil {
		return err
	}
	return nil
}

func writeError(w http.ResponseWriter, errorCode int, err error) error {
	var response errorResponse
	response.Error.Status = http.StatusText(errorCode)
	response.Error.Message = err.Error()
	return writeResult(w, errorCode, response)
}

type errorResponse struct {
	Error struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	} `json:"error"`
}
