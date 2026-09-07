package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/auth"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/eliasvasylenko/secret-agent/internal/store"
)

// DefaultMaxPollDuration is the maximum time an operation result poll may block.
const DefaultMaxPollDuration = 5 * time.Second

type Controller struct {
	secretStore  store.Store
	operations   sync.Map
	middleware   func(perms auth.Permissions, next http.HandlerFunc) http.Handler
	operationTtl time.Duration
}

type operationMapKey struct {
	secretId        string
	instanceId      string
	operationNumber int
}

func NewController(secretStore store.Store, limiter limiter, permissions permissions, operationTtl time.Duration) *Controller {
	limiterKey := func(r *http.Request) string {
		return identityFromContext(r.Context()).Principal
	}
	middleware := func(perms auth.Permissions, next http.HandlerFunc) http.Handler {
		return permissions.Middleware(perms, limiter.Middleware(limiterKey, next))
	}
	return &Controller{
		secretStore:  secretStore,
		operations:   sync.Map{},
		middleware:   middleware,
		operationTtl: operationTtl,
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
	registerHandler("GET /secrets/{secretId}/instances/{instanceId}/operations/{opNumber}/result", c.middleware(
		auth.Permissions{auth.Instances: auth.Read},
		c.operationResult,
	))
	registerHandler("POST /secrets/{secretId}/instances/{instanceId}/operations/{opNumber}/attach/{stream}", c.middleware(
		auth.Permissions{auth.Instances: auth.Write},
		c.attachProcess,
	))
	registerHandler("DELETE /secrets/{secretId}/instances/{instanceId}/operations/{opNumber}", c.middleware(
		auth.Permissions{auth.Instances: auth.Read},
		c.cancelOperation,
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
	from, to, err := parseRange(r)
	insts, err := instances.List(r.Context(), int(from), int(to))
	if err != nil {
		writeError(w, NewErrorResponse(http.StatusBadRequest, err))
		return
	}
	writeResult(w, ItemsResponse[secrets.Instances]{insts}, http.StatusOK)
}

func (s *Controller) createInstance(w http.ResponseWriter, r *http.Request) {
	secretId := r.PathValue("secretId")
	instances := s.secretStore.Instances(secretId)
	var operationParameters OperationParameters
	err := readBody(r, &operationParameters)
	if err != nil {
		writeError(w, err)
		return
	}
	identity := identityFromContext(r.Context())
	if identity == nil {
		writeError(w, NewErrorResponse(http.StatusInternalServerError, fmt.Errorf("identity not found in context")))
		return
	}
	parameters := executor.OperationParameters{
		Env:       operationParameters.Env,
		Forced:    operationParameters.Forced,
		Reason:    operationParameters.Reason,
		StartedBy: identity.Principal,
	}
	pipes, stdio := newOperationPipes()
	instance, err := instances.Create(r.Context(), parameters, stdio)
	if err != nil {
		closeOperationPipes(pipes)
		writeError(w, err)
		return
	}
	s.trackOperation(identity.Principal, instance, pipes)
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
	from, to, err := parseRange(r)
	if err != nil {
		writeError(w, err)
		return
	}
	instances := s.secretStore.Instances(secretId)
	operations, err := instances.Operations(instanceId).List(r.Context(), int(from), int(to))
	if err != nil {
		writeError(w, err)
		return
	}
	writeResult(w, operations, http.StatusOK)
}

func (s *Controller) createOperation(w http.ResponseWriter, r *http.Request) {
	secretId := r.PathValue("secretId")
	instanceId := r.PathValue("instanceId")
	var operationParameters CreateOperationParameters
	err := readBody(r, &operationParameters)
	if err != nil {
		writeError(w, err)
		return
	}

	identity := identityFromContext(r.Context())
	if identity == nil {
		writeError(w, NewErrorResponse(http.StatusUnauthorized, fmt.Errorf("identity not found in context")))
		return
	}
	parameters := executor.OperationParameters{
		Env:       operationParameters.Env,
		Forced:    operationParameters.Forced,
		Reason:    operationParameters.Reason,
		StartedBy: identity.Principal,
	}
	instances := s.secretStore.Instances(secretId)

	pipes, stdio := newOperationPipes()
	var instance *secrets.Instance
	switch operationParameters.Name {
	case secrets.Activate:
		instance, err = instances.Activate(r.Context(), instanceId, parameters, stdio)
	case secrets.Deactivate:
		instance, err = instances.Deactivate(r.Context(), instanceId, parameters, stdio)
	case secrets.Destroy:
		instance, err = instances.Destroy(r.Context(), instanceId, parameters, stdio)
	case secrets.Test:
		instance, err = instances.Test(r.Context(), instanceId, parameters, stdio)
	default:
		closeOperationPipes(pipes)
		writeError(w, NewErrorResponse(http.StatusBadRequest, fmt.Errorf("Cannot post operation %s", operationParameters.Name)))
		return
	}
	if err != nil {
		closeOperationPipes(pipes)
		writeError(w, err)
		return
	}

	s.trackOperation(identity.Principal, instance, pipes)
	writeResult(w, instance, http.StatusOK)
}

// register pipe handles for an in-flight operation and close them once the store reports completion.
func (s *Controller) trackOperation(startedBy string, instance *secrets.Instance, pipes *operationPipes) {
	op := &operation{
		pipes:     pipes,
		startedBy: startedBy,
		done:      make(chan struct{}),
	}
	opNumber := instance.Status.OperationNumber
	key := operationMapKey{secretId: instance.Secret.Id, instanceId: instance.Id, operationNumber: opNumber}
	s.operations.Store(key, op)

	go func() {
		defer close(op.done)
		instances := s.secretStore.Instances(instance.Secret.Id)
		if _, _, err := instances.Operations(instance.Id).Await(context.Background(), opNumber); err != nil {
			log.Printf("operation %d await: %v", opNumber, err)
		}
		closeOperationPipes(pipes)
		time.AfterFunc(s.operationTtl, func() {
			s.operations.Delete(key)
		})
	}()
}

func (s *Controller) operationResult(w http.ResponseWriter, r *http.Request) {
	secretId := r.PathValue("secretId")
	instanceId := r.PathValue("instanceId")
	opNumber, err := parsePath(r, "opNumber", strconv.Atoi)
	if err != nil {
		writeError(w, err)
		return
	}

	key := operationMapKey{secretId: secretId, instanceId: instanceId, operationNumber: opNumber}
	load, ok := s.operations.Load(key)

	maxWait, err := parseQuery(r, "maxWait", time.ParseDuration, DefaultMaxPollDuration)
	if err != nil {
		writeError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), maxWait)
	defer cancel()

	if ok {
		op := load.(*operation)
		select {
		case <-op.done:
		case <-ctx.Done():
			writeError(w, NewErrorResponse(http.StatusRequestTimeout, ctx.Err()))
			return
		}
	}

	instances := s.secretStore.Instances(secretId)
	_, instance, err := instances.Operations(instanceId).Await(ctx, opNumber)
	if err != nil {
		writeError(w, err)
		return
	}
	writeResult(w, instance, http.StatusOK)
}

func (s *Controller) cancelOperation(w http.ResponseWriter, r *http.Request) {
	secretId := r.PathValue("secretId")
	instanceId := r.PathValue("instanceId")
	opNumber, err := parsePath(r, "opNumber", strconv.Atoi)
	if err != nil {
		writeError(w, err)
		return
	}

	instances := s.secretStore.Instances(secretId)
	if err := instances.Operations(instanceId).Cancel(r.Context(), opNumber); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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

func parsePath[T any](r *http.Request, name string, parser func(s string) (T, error)) (T, error) {
	numString := r.PathValue(name)
	if numString == "" {
		var empty T
		return empty, NewErrorResponse(http.StatusBadRequest, fmt.Errorf("missing required parameter: %s", name))
	}
	value, err := parser(numString)
	if err != nil {
		var empty T
		return empty, NewErrorResponse(http.StatusBadRequest, fmt.Errorf("failed to parse '%s' - %w", name, err))
	}
	return value, nil
}
