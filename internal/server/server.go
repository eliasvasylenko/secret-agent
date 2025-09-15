package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/eliasvasylenko/secret-agent/internal/secret"
	"github.com/eliasvasylenko/secret-agent/internal/sqlite"
)

type Server struct {
	socket string
	store  secret.InstanceStore
	plans  secret.Plans
}

func New(socket string, plansFileName string, debug bool) (*Server, error) {
	store := sqlite.NewStore(debug)
	plans, err := secret.LoadPlans(plansFileName)
	if err != nil {
		return nil, err
	}

	server := &Server{
		socket: socket,
		store:  store,
		plans:  plans,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /secrets", func(w http.ResponseWriter, r *http.Request) {
		if secrets := loadSecrets(w, plans, store); secrets != nil {
			secrets.List(w)
		}
	})
	mux.HandleFunc("GET /secrets/{name}", func(w http.ResponseWriter, r *http.Request) {
		if secret := loadSecret(w, r, plans, store); secret != nil {
			secret.Show(w)
		}
	})
	mux.HandleFunc("POST /secrets/{name}", func(w http.ResponseWriter, r *http.Request) {
		if secret := loadSecret(w, r, plans, store); secret != nil {
			secret.CreateInstance()
		}
	})
	mux.HandleFunc("GET /secrets/{name}/instances/{instance}", func(w http.ResponseWriter, r *http.Request) {
		if instance := loadInstance(w, r, plans, store); instance != nil {
			instance.Show(w)
		}
	})
	mux.HandleFunc("DELETE /secrets/{name}/instances/{instance}", func(w http.ResponseWriter, r *http.Request) {
		if instance := loadInstance(w, r, plans, store); instance != nil {
			force := getBool(r, "force")
			instance.Destroy(force)
		}
	})
	mux.HandleFunc("PATCH /secrets/{name}/instances/{instance}", func(w http.ResponseWriter, r *http.Request) {
		if instance := loadInstance(w, r, plans, store); instance != nil {
			if patch := getPatch(w, r); patch != nil {
				force := getBool(r, "force")
				switch patch.Status {
				case secret.Active:
					instance.Activate(force)
				case secret.Inactive:
					instance.Deactivate(force)
				}
			}
		}
	})

	return server, nil
}

type InstancePatch struct {
	// The plan for managing this secret
	Status secret.InstanceStatus `json:"status"`
}

func getPatch(w http.ResponseWriter, r *http.Request) *InstancePatch {
	var patch InstancePatch
	body, _ := io.ReadAll(r.Body)
	err := json.Unmarshal(body, &patch)
	if err != nil {
		writeError(w, 400, err)
	} else if patch.Status != secret.Active && patch.Status != secret.Inactive {
		writeError(w, 400, fmt.Errorf("Cannot patch status %s", patch.Status))
	} else {
		return &patch
	}
	return nil
}

func getBool(r *http.Request, name string) bool {
	force := r.URL.Query()[name]
	if len(force) != 1 {
		return false
	}
	return strings.ToLower(force[0]) == "true"
}

func loadSecrets(w http.ResponseWriter, plans secret.Plans, store secret.InstanceStore) secret.Secrets {
	secrets, err := secret.NewSecrets(plans, store)
	if err != nil {
		writeError(w, 500, err)
	}
	return secrets
}

func loadSecret(w http.ResponseWriter, r *http.Request, plans secret.Plans, store secret.InstanceStore) *secret.Secret {
	name := r.PathValue("name")
	secret, err := secret.New(plans[name], name, store)
	if err != nil {
		writeError(w, 500, err)
	}
	return secret
}

func loadInstance(w http.ResponseWriter, r *http.Request, plans secret.Plans, store secret.InstanceStore) *secret.Instance {
	secret := loadSecret(w, r, plans, store)
	id := r.PathValue("id")
	instance, err := secret.GetInstance(id)
	if err != nil {
		writeError(w, 500, err)
	}
	return instance
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

type errorResponse struct {
	Error struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeError(w http.ResponseWriter, code int, err error) error {
	w.WriteHeader(code)

	var response errorResponse
	response.Error.Status = http.StatusText(code)
	response.Error.Message = err.Error()

	bytes, err := json.Marshal(response)
	if err != nil {
		return err
	}
	_, err = w.Write(bytes)
	if err != nil {
		return err
	}
	return nil
}
