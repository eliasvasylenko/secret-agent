package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/auth"
	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/eliasvasylenko/secret-agent/internal/store"
)

// defaultStreamReadChunk is used when MaxBytes is unset (0): each stream poll reads up to this many bytes.
const defaultMaxBytes = 1 << 10

type Controller struct {
	secretStore  store.Secrets
	operations   sync.Map
	middleware   func(perms auth.Permissions, next http.HandlerFunc) http.Handler
	newStream    func() Stream
	maxBytes     int
	operationTtl time.Duration
}

type operationMapKey struct {
	secretId        string
	instanceId      string
	operationNumber int
}

func NewController(secretStore store.Secrets, limiter limiter, permissions permissions, maxBytes int, operationTtl time.Duration) *Controller {
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
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
		newStream:    func() Stream { return newStream() },
		maxBytes:     maxBytes,
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
	registerHandler("GET /secrets/{secretId}/instances/{instanceId}/operations/{opNumber}/await", c.middleware(
		auth.Permissions{auth.Instances: auth.Write},
		c.awaitOperation,
	))
	registerHandler("GET /secrets/{secretId}/instances/{instanceId}/operations/{opNumber}/stdout", c.middleware(
		auth.Permissions{auth.Instances: auth.Write},
		c.streamStdout,
	))
	registerHandler("GET /secrets/{secretId}/instances/{instanceId}/operations/{opNumber}/stderr", c.middleware(
		auth.Permissions{auth.Instances: auth.Write},
		c.streamStderr,
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
	stdout := s.newStream()
	stderr := s.newStream()
	stdio := command.Stdio{Stdin: operationParameters.Input, Stdout: stdout, Stderr: stderr}
	instance, err := instances.Create(r.Context(), parameters, stdio)
	if err != nil {
		closeOperationStreams(stdout, stderr)
		writeError(w, err)
		return
	}
	s.trackOperation(stdout, stderr, identity.Principal, instances, instance)
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
	operations, err := instances.History(r.Context(), instanceId, int(from), int(to))
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

	stdout := s.newStream()
	stderr := s.newStream()
	stdio := command.Stdio{Stdin: operationParameters.Input, Stdout: stdout, Stderr: stderr}

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
		closeOperationStreams(stdout, stderr)
		writeError(w, NewErrorResponse(http.StatusBadRequest, fmt.Errorf("Cannot post operation %s", operationParameters.Name)))
		return
	}
	if err != nil {
		closeOperationStreams(stdout, stderr)
		writeError(w, err)
		return
	}

	s.trackOperation(stdout, stderr, identity.Principal, instances, instance)
	writeResult(w, instance, http.StatusOK)
}

func (s *Controller) trackOperation(stdout Stream, stderr Stream, startedBy string, instances store.Instances, instance *secrets.Instance) {
	op := &operation{
		Stdout:    stdout,
		Stderr:    stderr,
		startedBy: startedBy,
	}
	opNumber := instance.Status.OperationNumber
	key := operationMapKey{secretId: instance.Secret.Name, instanceId: instance.Id, operationNumber: opNumber}
	s.operations.Store(key, op)
	go func() {
		_, err := instances.Await(context.Background(), instance.Id, opNumber)
		var staleErr *store.StaleOperationError
		if !errors.As(err, &staleErr) {
			log.Printf("error awaiting operation %d: %v", opNumber, err)
		}
		if err := stdout.Close(); err != nil {
			log.Printf("error closing stdout: %v", err)
		}
		if err := stderr.Close(); err != nil {
			log.Printf("error closing stderr: %v", err)
		}
		time.AfterFunc(s.operationTtl, func() {
			s.operations.Delete(key)
		})
	}()
}

func (s *Controller) awaitOperation(w http.ResponseWriter, r *http.Request) {
	secretId := r.PathValue("secretId")
	instanceId := r.PathValue("instanceId")
	opNumber, err := parseNumber(r, "opNumber", nil)
	if err != nil {
		writeError(w, err)
		return
	}

	instances := s.secretStore.Instances(secretId)
	instance, err := instances.Await(r.Context(), instanceId, opNumber)
	if err != nil {
		writeError(w, err)
		return
	}
	writeResult(w, instance, http.StatusOK)
}

func (s *Controller) streamStdout(w http.ResponseWriter, r *http.Request) {
	s.handleStream(w, r, func(op *operation) Stream { return op.Stdout })
}

func (s *Controller) streamStderr(w http.ResponseWriter, r *http.Request) {
	s.handleStream(w, r, func(op *operation) Stream { return op.Stderr })
}

func (s *Controller) handleStream(w http.ResponseWriter, r *http.Request, pickStream func(*operation) Stream) {
	secretId := r.PathValue("secretId")
	instanceId := r.PathValue("instanceId")
	opNumber, err := parseNumber(r, "opNumber", nil)
	if err != nil {
		writeError(w, err)
		return
	}

	identity := identityFromContext(r.Context())
	if identity == nil {
		writeError(w, NewErrorResponse(http.StatusInternalServerError, fmt.Errorf("identity not found in context")))
		return
	}
	key := operationMapKey{secretId: secretId, instanceId: instanceId, operationNumber: opNumber}
	load, ok := s.operations.Load(key)
	if !ok {
		writeError(w, NewErrorResponse(http.StatusNotFound, fmt.Errorf("operation %d not found", opNumber)))
		return
	}
	op := load.(*operation)
	if identity.Principal != op.startedBy {
		writeError(w, NewErrorResponse(http.StatusForbidden, fmt.Errorf("operation %d was started by a different principal", opNumber)))
		return
	}

	fromByte, _ := parseInt(r, "fromByte", 0)
	maxBytes, err := parseInt(r, "maxBytes", s.maxBytes)
	if err != nil {
		writeError(w, err)
		return
	}
	if maxBytes <= 0 {
		maxBytes = s.maxBytes
	}
	maxWait := parseDuration(r, "maxWait", 5*time.Second)

	ctx, cancel := context.WithTimeout(r.Context(), maxWait)
	defer cancel()
	writeBytes(ctx, w, pickStream(op), fromByte, maxBytes)
}

func closeOperationStreams(stdout Stream, stderr Stream) {
	_ = stdout.Close()
	_ = stderr.Close()
}

func parseNumber(r *http.Request, param string, defaultValue *int) (int, error) {
	s := r.PathValue(param)
	if s == "" {
		if defaultValue == nil {
			return 0, NewErrorResponse(http.StatusBadRequest, fmt.Errorf("missing required parameter: %s", param))
		}
		return *defaultValue, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, NewErrorResponse(http.StatusBadRequest, fmt.Errorf("invalid operation number: %s", s))
	}
	return n, nil
}

func parseDuration(r *http.Request, param string, defaultValue time.Duration) time.Duration {
	s := r.URL.Query().Get(param)
	if s == "" {
		return defaultValue
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return defaultValue
	}
	return d
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

func parseRange(r *http.Request) (int, int, error) {
	from, err := parseInt(r, "from", 32)
	if err != nil {
		return from, 0, err
	}
	to, err := parseInt(r, "to", 32)
	return from, to, err
}

func parseInt(r *http.Request, name string, defaultValue int) (int, error) {
	numString := r.URL.Query().Get(name)
	if numString == "" {
		return defaultValue, nil
	}
	num, err := strconv.ParseInt(numString, 10, 32)
	if err != nil {
		return 0, NewErrorResponse(http.StatusBadRequest, fmt.Errorf("failed to parse '%s' - %w", name, err))
	}
	return int(num), nil
}
