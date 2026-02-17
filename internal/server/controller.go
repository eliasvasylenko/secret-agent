package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/eliasvasylenko/secret-agent/internal/auth"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/eliasvasylenko/secret-agent/internal/store"
)

type Controller struct {
	secretStore store.Secrets
	middleware  func(perms auth.Permissions, next http.HandlerFunc) http.Handler
}

func NewController(secretStore store.Secrets, limiter limiter, permissions permissions) *Controller {
	limiterKey := func(r *http.Request) string {
		return identityFromContext(r.Context()).Principal
	}
	middleware := func(perms auth.Permissions, next http.HandlerFunc) http.Handler {
		return limiter.Middleware(limiterKey, permissions.Middleware(perms, next))
	}
	return &Controller{
		secretStore: secretStore,
		middleware:  middleware,
	}
}

type limiter interface {
	Middleware(keyFunc func(r *http.Request) string, next http.Handler) http.Handler
}

type permissions interface {
	Middleware(perms auth.Permissions, next http.Handler) http.Handler
}

func (c *Controller) buildHandler(registerHandler func(pattern string, handler http.Handler)) {
	registerHandler("GET /secrets", c.middleware(
		auth.Permissions{auth.Secrets: auth.List},
		c.listSecrets,
	))
	registerHandler("GET /secrets/{secretId}", c.middleware(
		auth.Permissions{auth.Secrets: auth.Read},
		c.getSecret,
	))
	registerHandler("GET /secrets/{secretId}/instances", c.middleware(
		auth.Permissions{auth.Instances: auth.Read},
		c.listInstances,
	))
	registerHandler("POST /secrets/{secretId}/instances", c.middleware(
		auth.Permissions{auth.Instances: auth.Write},
		c.createInstance,
	))
	registerHandler("GET /secrets/{secretId}/instances/{instanceId}", c.middleware(
		auth.Permissions{auth.Instances: auth.Read},
		c.getInstance,
	))
	registerHandler("GET /secrets/{secretId}/instances/{instanceId}/operations", c.middleware(
		auth.Permissions{auth.Instances: auth.Read},
		c.getOperations,
	))
	registerHandler("POST /secrets/{secretId}/instances/{instanceId}/operations", c.middleware(
		auth.Permissions{auth.Secrets: auth.Write, auth.Instances: auth.Write},
		c.createOperation,
	))
}

func (s *Controller) listSecrets(w http.ResponseWriter, r *http.Request) {
	secs, err := s.secretStore.List(r.Context())
	if err != nil {
		writeError(w, NewErrorResponse(http.StatusBadRequest, err))
		return
	}
	writeResult(w, ItemsResponse[secrets.Secrets]{secs}, http.StatusOK)
}

func (s *Controller) getSecret(w http.ResponseWriter, r *http.Request) {
	secretId := r.PathValue("secretId")
	secret, err := s.secretStore.Get(r.Context(), secretId)
	if err != nil {
		writeError(w, NewErrorResponse(http.StatusBadRequest, err))
		return
	}
	writeResult(w, secret, http.StatusOK)
}

func (s *Controller) listInstances(w http.ResponseWriter, r *http.Request) {
	secretId := r.PathValue("secretId")
	instances := s.secretStore.Instances(secretId)
	from, to, err := parseRange(*r.URL)
	insts, err := instances.List(r.Context(), from, to)
	if err != nil {
		writeError(w, NewErrorResponse(http.StatusBadRequest, err))
		return
	}
	writeResult(w, ItemsResponse[secrets.Instances]{insts}, http.StatusOK)
}

func (s *Controller) createInstance(w http.ResponseWriter, r *http.Request) {
	secretId := r.PathValue("secretId")
	instances := s.secretStore.Instances(secretId)
	var operation OperationParameters
	err := readBody(r, &operation)
	if err != nil {
		writeError(w, err)
		return
	}
	identity := identityFromContext(r.Context())
	if identity == nil {
		writeError(w, NewErrorResponse(http.StatusInternalServerError, fmt.Errorf("identity not found in context")))
		return
	}
	parameters := secrets.OperationParameters{
		Env:       operation.Env,
		Forced:    operation.Forced,
		Reason:    operation.Reason,
		StartedBy: identity.Principal,
	}
	instance, err := instances.Create(r.Context(), parameters)
	if err != nil {
		writeError(w, err)
		return
	}
	writeResult(w, instance, http.StatusOK)
}

func (s *Controller) getInstance(w http.ResponseWriter, r *http.Request) {
	secretId := r.PathValue("secretId")
	instanceId := r.PathValue("instanceId")
	instances := s.secretStore.Instances(secretId)
	instance, err := instances.Get(r.Context(), instanceId)
	if err != nil {
		writeError(w, err)
		return
	}
	writeResult(w, instance, http.StatusOK)
}

func (s *Controller) getOperations(w http.ResponseWriter, r *http.Request) {
	secretId := r.PathValue("secretId")
	instanceId := r.PathValue("instanceId")
	from, to, err := parseRange(*r.URL)
	instances := s.secretStore.Instances(secretId)
	operations, err := instances.History(r.Context(), instanceId, int(from), int(to))
	if err != nil {
		writeError(w, err)
	}
	writeResult(w, operations, http.StatusOK)
}

func (s *Controller) createOperation(w http.ResponseWriter, r *http.Request) {
	secretId := r.PathValue("secretId")
	instanceId := r.PathValue("instanceId")
	var operation CreateOperationParameters
	err := readBody(r, &operation)
	if err != nil {
		writeError(w, err)
		return
	}

	identity := identityFromContext(r.Context())
	if identity == nil {
		writeError(w, NewErrorResponse(http.StatusInternalServerError, fmt.Errorf("identity not found in context")))
		return
	}
	parameters := secrets.OperationParameters{
		Env:       operation.Env,
		Forced:    operation.Forced,
		Reason:    operation.Reason,
		StartedBy: identity.Principal,
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
		writeError(w, NewErrorResponse(http.StatusBadRequest, fmt.Errorf("Cannot post operation %s", operation.Name)))
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	writeResult(w, instance, http.StatusOK)
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
