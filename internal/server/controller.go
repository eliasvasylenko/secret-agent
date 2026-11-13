package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/auth"
	"github.com/eliasvasylenko/secret-agent/internal/backend"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
)

type Controller struct {
	secretStore backend.Backend
	operations  operationMap
	leases      operationLeases
	middleware  func(perms auth.Permissions, next http.HandlerFunc) http.Handler
}

func NewController(secretStore backend.Backend, policy *auth.Policy, limiter *Limiter, pendingTTL, finishedTTL time.Duration) *Controller {
	limiterKey := func(r *http.Request) string {
		return identityFromContext(r.Context()).Principal.GetName()
	}
	middleware := func(perms auth.Permissions, next http.HandlerFunc) http.Handler {
		return AuthMiddleware(policy, perms, limiter.Middleware(limiterKey, next))
	}
	return &Controller{
		secretStore: secretStore,
		leases:      newOperationLeases(pendingTTL, finishedTTL),
		middleware:  middleware,
	}
}

type noopProposer struct{}

func (noopProposer) Propose(context.Context, string, secrets.OperationName, executor.OperationParameters, io.ReadWriteCloser) error {
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
	registerHandler("GET /secrets/{secretId}/active", c.middleware(
		auth.Permissions{auth.Instances: auth.Read},
		c.getActiveInstance,
	))
	registerHandler("GET /instances", c.middleware(
		auth.Permissions{auth.Instances: auth.Read},
		c.listInstances,
	))
	registerHandler("GET /instances/{instanceId}", c.middleware(
		auth.Permissions{auth.Instances: auth.Read},
		c.getInstance,
	))
	registerHandler("POST /operations", c.middleware(
		auth.Permissions{auth.Secrets: auth.Write, auth.Instances: auth.Write},
		c.createOperation,
	))
	registerHandler("GET /operations/{operationId}", c.middleware(
		auth.Permissions{auth.Instances: auth.Read},
		c.getOperation,
	))
	registerHandler("POST /operations/{operationId}/attach", c.middleware(
		auth.Permissions{auth.Instances: auth.Write},
		c.attachOperation,
	))
	registerHandler("POST /operations/{operationId}/start", c.middleware(
		auth.Permissions{auth.Secrets: auth.Write, auth.Instances: auth.Write},
		c.startOperation,
	))
	registerHandler("DELETE /operations/{operationId}", c.middleware(
		auth.Permissions{auth.Instances: auth.Write},
		c.deleteOperation,
	))
}

func (s *Controller) listSecrets(w http.ResponseWriter, r *http.Request) {
	secs, err := s.secretStore.Catalog().Secrets().List(r.Context())
	if err != nil {
		writeError(w, NewErrorResponse(http.StatusBadRequest, err))
		return
	}
	var visible secrets.Secrets
	if secs != nil {
		visible = make(secrets.Secrets, len(secs))
		for id, secret := range secs {
			if permitted(r, id) {
				visible[id] = secret
			}
		}
	}
	writeResult(w, ItemsResponse[secrets.Secrets]{visible}, http.StatusOK)
}

func (s *Controller) getSecret(w http.ResponseWriter, r *http.Request) {
	secretId := r.PathValue("secretId")
	if !requirePermission(w, r, secretId) {
		return
	}
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
	if secretId != nil && !requirePermission(w, r, *secretId) {
		return
	}
	insts, err := s.secretStore.Catalog().Instances().List(r.Context(), secretId, int(from), int(to))
	if err != nil {
		writeError(w, NewErrorResponse(http.StatusBadRequest, err))
		return
	}
	var visible secrets.Instances
	if insts != nil {
		visible = make(secrets.Instances, len(insts))
		for id, instance := range insts {
			if instance != nil && permitted(r, instance.Secret.Id) {
				visible[id] = instance
			}
		}
	}
	writeResult(w, ItemsResponse[secrets.Instances]{visible}, http.StatusOK)
}

func (s *Controller) getActiveInstance(w http.ResponseWriter, r *http.Request) {
	secretId := r.PathValue("secretId")
	if !requirePermission(w, r, secretId) {
		return
	}
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
	if instance != nil && !requirePermission(w, r, instance.Secret.Id) {
		return
	}
	writeResult(w, instance, http.StatusOK)
}

// createOperation records a pending operation. It never runs anything; the
// operation runs when its creator posts start, with the streams attached.
func (s *Controller) createOperation(w http.ResponseWriter, r *http.Request) {
	identity := identityFromContext(r.Context())
	if identity == nil {
		writeError(w, NewErrorResponse(http.StatusUnauthorized, fmt.Errorf("identity not found in context")))
		return
	}

	var request StartOperationRequest
	if err := readBody(r, &request); err != nil {
		writeError(w, err)
		return
	}

	secretId, instanceId := request.SecretId, request.InstanceId
	switch {
	case request.Name == secrets.Create:
		if secretId == "" {
			writeError(w, NewErrorResponse(http.StatusBadRequest, fmt.Errorf("secretId required")))
			return
		}
		if instanceId != "" {
			writeError(w, NewErrorResponse(http.StatusBadRequest, fmt.Errorf("instanceId must be empty for create")))
			return
		}
		secret, err := s.secretStore.Catalog().Secrets().Get(r.Context(), secretId)
		if err != nil || secret == nil {
			writeError(w, NewErrorResponse(http.StatusNotFound, fmt.Errorf("unknown secret %s", secretId)))
			return
		}
	case isInstanceOperation(request.Name):
		if instanceId == "" {
			writeError(w, NewErrorResponse(http.StatusBadRequest, fmt.Errorf("instanceId required")))
			return
		}
		// The secret comes from the instance, so a request cannot name one
		// secret while operating on another secret's instance.
		instance, err := s.secretStore.Catalog().Instances().Get(r.Context(), instanceId)
		if err != nil || instance == nil {
			writeError(w, NewErrorResponse(http.StatusNotFound, fmt.Errorf("unknown instance %s", instanceId)))
			return
		}
		if secretId != "" && secretId != instance.Secret.Id {
			writeError(w, NewErrorResponse(http.StatusBadRequest, fmt.Errorf("secretId %s does not match instance secret %s", secretId, instance.Secret.Id)))
			return
		}
		secretId = instance.Secret.Id
	default:
		writeError(w, NewErrorResponse(http.StatusBadRequest, fmt.Errorf("cannot post operation %s", request.Name)))
		return
	}

	entry := newOperationEntry(identity.Principal.GetName(), secretId, instanceId, request.Name, executor.OperationParameters{
		Env:    request.Env,
		Forced: request.Forced,
		Reason: request.Reason,
	}, s.leases)
	s.operations.add(entry)
	snapshot, err := entry.snapshot()
	if err != nil {
		writeError(w, err)
		return
	}
	writeResult(w, OperationCreatedResponse{
		OperationID: snapshot.Operation.Id,
		State:       snapshot.State,
		ExpiresAt:   snapshot.ExpiresAt,
	}, http.StatusCreated)
}

func isInstanceOperation(name secrets.OperationName) bool {
	switch name {
	case secrets.Activate, secrets.Deactivate, secrets.Destroy, secrets.Test:
		return true
	default:
		return false
	}
}

func (s *Controller) getOperation(w http.ResponseWriter, r *http.Request) {
	entry, ok := s.operationForCreator(w, r)
	if !ok {
		return
	}
	untilDone, err := parseUntilDone(r)
	if err != nil {
		writeError(w, err)
		return
	}
	if untilDone > 0 {
		entry.wait(r.Context(), untilDone)
	}
	snapshot, err := entry.snapshot()
	if err != nil {
		writeError(w, err)
		return
	}
	writeResult(w, snapshot, http.StatusOK)
}

func (s *Controller) startOperation(w http.ResponseWriter, r *http.Request) {
	entry, ok := s.operationForCreator(w, r)
	if !ok {
		return
	}
	if !s.mayStart(w, r, identityFromContext(r.Context()), entry.secretId()) {
		return
	}
	if err := entry.start(); err != nil {
		writeError(w, err)
		return
	}

	op := entry.operation()
	params := entry.params
	params.CreatedBy = op.CreatedBy
	params.CreatedAt = op.CreatedAt
	params.StartedBy = op.CreatedBy
	// r.Context() is the accept ctx for Run (persist only); execute uses Handle.
	instance, handle, err := s.secretStore.Runner(op.SecretId).Run(
		r.Context(), op.Name, op.InstanceId, params, noopProposer{}, entry.files(),
	)
	if err != nil {
		// Rejected at accept: the operation has failed, and stays readable as such.
		s.operations.finish(entry, nil, err)
		writeError(w, err)
		return
	}
	entry.started(instance)
	s.operations.watch(entry, handle)
	writeResult(w, instance, http.StatusOK)
}

func (s *Controller) deleteOperation(w http.ResponseWriter, r *http.Request) {
	entry, ok := s.operationForCreator(w, r)
	if !ok {
		return
	}
	if err := s.operations.cancel(entry); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// operationForCreator loads the operation named in the URL and checks the caller created it.
func (s *Controller) operationForCreator(w http.ResponseWriter, r *http.Request) (*operationEntry, bool) {
	identity := identityFromContext(r.Context())
	if identity == nil {
		writeError(w, NewErrorResponse(http.StatusUnauthorized, fmt.Errorf("identity not found in context")))
		return nil, false
	}
	entry, err := s.operations.get(r.PathValue("operationId"))
	if err != nil {
		writeError(w, err)
		return nil, false
	}
	if entry.createdBy() != identity.Principal.GetName() {
		writeError(w, NewErrorResponse(http.StatusForbidden, fmt.Errorf("operation not created by this principal")))
		return nil, false
	}
	return entry, true
}

// mayStart is the permission gate at start: whoever starts must hold the grant,
// and a secret that names parents only runs for one of them.
func (s *Controller) mayStart(w http.ResponseWriter, r *http.Request, identity *auth.Identity, secretID string) bool {
	parents, err := s.secretParents(r.Context(), secretID)
	if err != nil {
		writeError(w, err)
		return false
	}
	if len(parents) > 0 && !hasParentRole(identity, parents) {
		writeError(w, NewErrorResponse(http.StatusForbidden, errors.New("operation not permitted")))
		return false
	}
	if !permitted(r, secretID) {
		writeError(w, NewErrorResponse(http.StatusForbidden, errors.New("operation not permitted")))
		return false
	}
	return true
}

func (s *Controller) secretParents(ctx context.Context, secretID string) ([]secrets.Parent, error) {
	secret, err := s.secretStore.Catalog().Secrets().Get(ctx, secretID)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, fmt.Errorf("unknown secret %s", secretID)
	}
	return secret.Parents, nil
}

func hasParentRole(identity *auth.Identity, parents []secrets.Parent) bool {
	for _, parent := range parents {
		if identity.HasRole(parent) {
			return true
		}
	}
	return false
}

func parseRange(r *http.Request) (int64, int64, error) {
	from, err := parseQueryInt(r, "from", 0)
	if err != nil {
		return from, 0, err
	}
	to, err := parseQueryInt(r, "to", 10)
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

func parseUntilDone(r *http.Request) (time.Duration, error) {
	value := r.URL.Query().Get("untilDone")
	if value == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil || d < 0 {
		return 0, NewErrorResponse(http.StatusBadRequest, fmt.Errorf("untilDone must be a duration"))
	}
	return d, nil
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
