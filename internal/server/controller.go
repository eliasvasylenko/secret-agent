package server

import (
	"errors"
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
	approvalsMu sync.Mutex
	approvals   map[string]*parkedApproval
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
		approvals:   make(map[string]*parkedApproval),
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
	registerHandler("GET /secrets/{secretId}/active", c.middleware(
		auth.Permissions{auth.Instances: auth.Read},
		c.getActiveInstance,
	))
	registerHandler("POST /secrets/{secretId}/attach/{stream}", c.middleware(
		auth.Permissions{auth.Instances: auth.Write},
		c.attachSecret,
	))
	registerHandler("GET /instances", c.middleware(
		auth.Permissions{auth.Instances: auth.Read},
		c.listInstances,
	))
	registerHandler("GET /instances/{instanceId}", c.middleware(
		auth.Permissions{auth.Instances: auth.Read},
		c.getInstance,
	))
	registerHandler("POST /instances", c.middleware(
		auth.Permissions{auth.Instances: auth.Write},
		c.createInstance,
	))
	registerHandler("POST /instances/{instanceId}/approve", c.middleware(
		auth.Permissions{auth.Instances: auth.Write},
		c.approveInstance,
	))
	registerHandler("GET /operations", c.middleware(
		auth.Permissions{auth.Instances: auth.Read},
		c.listOperations,
	))
	registerHandler("POST /operations", c.middleware(
		auth.Permissions{auth.Secrets: auth.Write, auth.Instances: auth.Write},
		c.createOperation,
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
	from, to, err := parseRange(r)
	if err != nil {
		writeError(w, err)
		return
	}
	secretId := optionalQuery(r, "secretId")
	insts, err := s.secretStore.Catalog().Instances().List(r.Context(), secretId, int(from), int(to))
	if err != nil {
		writeError(w, NewErrorResponse(http.StatusBadRequest, err))
		return
	}
	writeResult(w, ItemsResponse[secrets.Instances]{insts}, http.StatusOK)
}

func (s *Controller) createInstance(w http.ResponseWriter, r *http.Request) {
	identity := identityFromContext(r.Context())
	if identity == nil {
		writeError(w, NewErrorResponse(http.StatusUnauthorized, fmt.Errorf("identity not found in context")))
		return
	}

	var request SecretOperationRequest
	if err := readBody(r, &request); err != nil {
		writeError(w, err)
		return
	}
	if request.SecretId == "" {
		writeError(w, NewErrorResponse(http.StatusBadRequest, fmt.Errorf("secretId required")))
		return
	}
	s.startAttachedRun(w, r, request.SecretId, "", secrets.Create, executor.OperationParameters{
		Env:       request.Env,
		Forced:    request.Forced,
		Reason:    request.Reason,
		StartedBy: identity.Principal,
	})
}

func (s *Controller) approveInstance(w http.ResponseWriter, r *http.Request) {
	identity := identityFromContext(r.Context())
	if identity == nil {
		writeError(w, NewErrorResponse(http.StatusUnauthorized, fmt.Errorf("identity not found in context")))
		return
	}
	instanceID := r.PathValue("instanceId")
	err := s.submitApproval(instanceID, identity.Principal)
	if errors.Is(err, errNoParkedApproval) {
		writeError(w, NewErrorResponse(http.StatusConflict, err))
		return
	}
	if errors.Is(err, backend.ErrNotApprover) {
		writeError(w, NewErrorResponse(http.StatusForbidden, err))
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	instance, err := s.secretStore.Catalog().Instances().Get(r.Context(), instanceID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeResult(w, instance, http.StatusOK)
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

func (s *Controller) listOperations(w http.ResponseWriter, r *http.Request) {
	from, to, err := parseRange(r)
	if err != nil {
		writeError(w, err)
		return
	}
	secretId := optionalQuery(r, "secretId")
	instanceId := optionalQuery(r, "instanceId")
	operations, err := s.secretStore.Catalog().Operations().List(r.Context(), secretId, instanceId, int(from), int(to))
	if err != nil {
		writeError(w, err)
		return
	}
	writeResult(w, operations, http.StatusOK)
}

func (s *Controller) createOperation(w http.ResponseWriter, r *http.Request) {
	identity := identityFromContext(r.Context())
	if identity == nil {
		writeError(w, NewErrorResponse(http.StatusUnauthorized, fmt.Errorf("identity not found in context")))
		return
	}

	var request InstanceOperationRequest
	if err := readBody(r, &request); err != nil {
		writeError(w, err)
		return
	}
	if !isInstanceOperation(request.Name) {
		writeError(w, NewErrorResponse(http.StatusBadRequest, fmt.Errorf("cannot post operation %s", request.Name)))
		return
	}
	if request.InstanceId == "" {
		writeError(w, NewErrorResponse(http.StatusBadRequest, fmt.Errorf("instanceId required")))
		return
	}

	// The secret comes from the instance, so a request cannot consume one
	// secret's attach slot while operating on another secret's instance.
	instance, err := s.secretStore.Catalog().Instances().Get(r.Context(), request.InstanceId)
	if err != nil {
		writeError(w, NewErrorResponse(http.StatusNotFound, err))
		return
	}
	if instance == nil {
		writeError(w, NewErrorResponse(http.StatusNotFound, fmt.Errorf("unknown instance %s", request.InstanceId)))
		return
	}

	s.startAttachedRun(w, r, instance.Secret.Id, request.InstanceId, request.Name, executor.OperationParameters{
		Env:       request.Env,
		Forced:    request.Forced,
		Reason:    request.Reason,
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
	// Propose parks until POST …/approve records an eligible principal and returns nil.
	proposer := newRunProposer(s, s.secretStore)
	instance, handle, err := s.secretStore.Runner(secretId).Run(
		r.Context(), name, instanceId, parameters, proposer, slot.pipes.Stdio(),
	)
	if err != nil {
		slot.close()
		writeError(w, err)
		return
	}
	proposer.bind(instance.Id)
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

// optionalQuery returns nil when the filter is absent, meaning "unfiltered".
func optionalQuery(r *http.Request, name string) *string {
	value := r.URL.Query().Get(name)
	if value == "" {
		return nil
	}
	return &value
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
