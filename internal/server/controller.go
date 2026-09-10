package server

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"

	"github.com/eliasvasylenko/secret-agent/internal/auth"
	"github.com/eliasvasylenko/secret-agent/internal/backend"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
)

type Controller struct {
	secretStore backend.Backend
	slotsMu     sync.Mutex
	slots       map[attachSlotKey]*attachSlot
	middleware  func(perms auth.Permissions, next http.HandlerFunc) http.Handler
}

func NewController(secretStore backend.Backend, limiter limiter, permissions permissions) *Controller {
	limiterKey := func(r *http.Request) string {
		return identityFromContext(r.Context()).Principal
	}
	middleware := func(perms auth.Permissions, next http.HandlerFunc) http.Handler {
		return permissions.Middleware(perms, limiter.Middleware(limiterKey, next))
	}
	return &Controller{
		secretStore: secretStore,
		slots:       make(map[attachSlotKey]*attachSlot),
		middleware:  middleware,
	}
}

type limiter interface {
	Middleware(keyFunc func(r *http.Request) string, next http.Handler) http.Handler
}

type permissions interface {
	Middleware(perms auth.Permissions, next http.Handler) http.Handler
}

type noopProposer struct{}

func (noopProposer) Propose(context.Context, secrets.OperationName, executor.OperationParameters) error {
	return nil
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
	registerHandler("GET /secrets/{secretId}/active", c.middleware(
		auth.Permissions{auth.Instances: auth.Read},
		c.getActiveInstance,
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
	registerHandler("POST /secrets/{secretId}/attach/{stream}", c.middleware(
		auth.Permissions{auth.Instances: auth.Write},
		c.attachSecret,
	))
}

func (s *Controller) listSecrets(w http.ResponseWriter, r *http.Request) {
	secs, err := s.secretStore.Catalog().Secrets().List(r.Context())
	if err != nil {
		writeError(w, NewErrorResponse(http.StatusBadRequest, err))
		return
	}
	writeResult(w, ItemsResponse[secrets.Secrets]{secs}, http.StatusOK)
}

func (s *Controller) getSecret(w http.ResponseWriter, r *http.Request) {
	secretId := r.PathValue("secretId")
	secret, err := s.secretStore.Catalog().Secrets().Get(r.Context(), secretId)
	if err != nil {
		writeError(w, NewErrorResponse(http.StatusBadRequest, err))
		return
	}
	writeResult(w, secret, http.StatusOK)
}

func (s *Controller) listInstances(w http.ResponseWriter, r *http.Request) {
	secretId := r.PathValue("secretId")
	from, to, err := parseRange(r)
	if err != nil {
		writeError(w, err)
		return
	}
	insts, err := s.secretStore.Catalog().Instances().List(r.Context(), &secretId, int(from), int(to))
	if err != nil {
		writeError(w, NewErrorResponse(http.StatusBadRequest, err))
		return
	}
	writeResult(w, ItemsResponse[secrets.Instances]{insts}, http.StatusOK)
}

func (s *Controller) createInstance(w http.ResponseWriter, r *http.Request) {
	secretId := r.PathValue("secretId")
	identity := identityFromContext(r.Context())
	if identity == nil {
		writeError(w, NewErrorResponse(http.StatusUnauthorized, fmt.Errorf("identity not found in context")))
		return
	}

	var opRequest OperationRequest
	if err := readBody(r, &opRequest); err != nil {
		writeError(w, err)
		return
	}
	s.startAttachedRun(w, r, secretId, "", secrets.Create, executor.OperationParameters{
		Env:       opRequest.Env,
		Forced:    opRequest.Forced,
		Reason:    opRequest.Reason,
		StartedBy: identity.Principal,
	})
}

func (s *Controller) getActiveInstance(w http.ResponseWriter, r *http.Request) {
	secretId := r.PathValue("secretId")
	instance, err := s.secretStore.Catalog().Instances().GetActive(r.Context(), secretId)
	if err != nil {
		writeError(w, err)
		return
	}
	writeResult(w, instance, http.StatusOK)
}

func (s *Controller) getInstance(w http.ResponseWriter, r *http.Request) {
	instanceId := r.PathValue("instanceId")
	instance, err := s.secretStore.Catalog().Instances().Get(r.Context(), instanceId)
	if err != nil {
		writeError(w, err)
		return
	}
	writeResult(w, instance, http.StatusOK)
}

func (s *Controller) getOperations(w http.ResponseWriter, r *http.Request) {
	secretId := r.PathValue("secretId")
	instanceId := r.PathValue("instanceId")
	from, to, err := parseRange(r)
	if err != nil {
		writeError(w, err)
		return
	}
	operations, err := s.secretStore.Catalog().Operations().List(r.Context(), &secretId, &instanceId, int(from), int(to))
	if err != nil {
		writeError(w, err)
		return
	}
	writeResult(w, operations, http.StatusOK)
}

func (s *Controller) createOperation(w http.ResponseWriter, r *http.Request) {
	secretId := r.PathValue("secretId")
	instanceId := r.PathValue("instanceId")

	identity := identityFromContext(r.Context())
	if identity == nil {
		writeError(w, NewErrorResponse(http.StatusUnauthorized, fmt.Errorf("identity not found in context")))
		return
	}

	var namedRequest NamedOperationRequest
	if err := readBody(r, &namedRequest); err != nil {
		writeError(w, err)
		return
	}
	if !isInstanceOperation(namedRequest.Name) {
		writeError(w, NewErrorResponse(http.StatusBadRequest, fmt.Errorf("cannot post operation %s", namedRequest.Name)))
		return
	}
	s.startAttachedRun(w, r, secretId, instanceId, namedRequest.Name, executor.OperationParameters{
		Env:       namedRequest.Env,
		Forced:    namedRequest.Forced,
		Reason:    namedRequest.Reason,
		StartedBy: identity.Principal,
	})
}

func isInstanceOperation(name secrets.OperationName) bool {
	switch name {
	case secrets.Activate, secrets.Deactivate, secrets.Destroy, secrets.Test:
		return true
	default:
		return false
	}
}

func (s *Controller) startAttachedRun(
	w http.ResponseWriter,
	r *http.Request,
	secretId, instanceId string,
	name secrets.OperationName,
	parameters executor.OperationParameters,
) {
	identity := identityFromContext(r.Context())
	slot, err := s.takeSlot(secretId, identity.Principal)
	if err != nil {
		writeError(w, err)
		return
	}

	// r.Context() is the accept ctx for Run (persist only); execute uses Handle.
	instance, handle, err := s.secretStore.Runner(secretId).Run(
		r.Context(), name, instanceId, parameters, noopProposer{}, slot.pipes.Stdio(),
	)
	if err != nil {
		slot.close()
		writeError(w, err)
		return
	}
	slot.watch(handle)
	writeResult(w, instance, http.StatusOK)
}

func parseRange(r *http.Request) (int64, int64, error) {
	from, err := parseQueryInt(r, "from", 32)
	if err != nil {
		return from, 0, err
	}
	to, err := parseQueryInt(r, "to", 32)
	return from, to, err
}

func parseQueryInt(r *http.Request, name string, defaultValue int64) (int64, error) {
	return parseQuery(r, name, func(s string) (int64, error) { return strconv.ParseInt(s, 10, 32) }, defaultValue)
}

func parseQuery[T any](r *http.Request, name string, parser func(s string) (T, error), defaultValue T) (T, error) {
	valueString := r.URL.Query().Get(name)
	if valueString == "" {
		return defaultValue, nil
	}
	value, err := parser(valueString)
	if err != nil {
		var empty T
		return empty, NewErrorResponse(http.StatusBadRequest, fmt.Errorf("failed to parse '%s' - %w", name, err))
	}
	return value, nil
}
