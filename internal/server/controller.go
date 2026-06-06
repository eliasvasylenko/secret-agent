package server

import (
	"context"
	"encoding/json"
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

// DefaultStdioPollDuration is the maximum time a process/io round may block per stream read.
const DefaultMaxPollDuration = 5 * time.Second

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
	registerHandler("GET /secrets/{secretId}/instances/{instanceId}/operations/{opNumber}/result", c.middleware(
		auth.Permissions{auth.Instances: auth.Read},
		c.operationResult,
	))
	registerHandler("DELETE /secrets/{secretId}/instances/{instanceId}/operations/{opNumber}/process", c.middleware(
		auth.Permissions{auth.Instances: auth.Write},
		c.cancelOperation,
	))
	registerHandler("POST /secrets/{secretId}/instances/{instanceId}/operations/{opNumber}/process/io", c.middleware(
		auth.Permissions{auth.Instances: auth.Read},
		c.exchangeStdio,
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
	stdout := s.newStream()
	stderr := s.newStream()
	stdin := s.newStream()
	stdio := command.Stdio{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
	}
	instance, err := instances.Create(r.Context(), parameters, stdio)
	if err != nil {
		closeOperationStreams(stdout, stderr, stdin)
		writeError(w, err)
		return
	}
	s.trackOperation(identity.Principal, instance, stdout, stderr, stdin)
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
	stdin := s.newStream()
	stdio := command.Stdio{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
	}
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
		closeOperationStreams(stdout, stderr, stdin)
		writeError(w, NewErrorResponse(http.StatusBadRequest, fmt.Errorf("Cannot post operation %s", operationParameters.Name)))
		return
	}
	if err != nil {
		closeOperationStreams(stdout, stderr, stdin)
		writeError(w, err)
		return
	}

	s.trackOperation(identity.Principal, instance, stdout, stderr, stdin)
	writeResult(w, instance, http.StatusOK)
}

func closeOperationStreams(stdout, stderr, stdin Stream) {
	_ = stdout.Close()
	_ = stderr.Close()
	if stdin != nil {
		_ = stdin.Close()
	}
}

// register stream handles for an in-flight operation and close them once the store reports completion.
func (s *Controller) trackOperation(startedBy string, instance *secrets.Instance, stdout, stderr, stdin Stream) {
	op := &operation{
		Stdout:    stdout,
		Stderr:    stderr,
		Stdin:     stdin,
		startedBy: startedBy,
		done:      make(chan struct{}),
	}
	opNumber := instance.Status.OperationNumber
	key := operationMapKey{secretId: instance.Secret.Id, instanceId: instance.Id, operationNumber: opNumber}
	s.operations.Store(key, op)

	go func() {
		defer close(op.done)
		instances := s.secretStore.Instances(instance.Secret.Id)
		if _, err := instances.Await(context.Background(), instance.Id, opNumber); err != nil {
			log.Printf("operation %d await: %v", opNumber, err)
		}
		if err := stdout.Close(); err != nil {
			log.Printf("error closing stdout: %v", err)
		}
		if err := stderr.Close(); err != nil {
			log.Printf("error closing stderr: %v", err)
		}
		if err := stdin.Close(); err != nil {
			log.Printf("error closing stdin: %v", err)
		}
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
	instance, err := instances.Await(ctx, instanceId, opNumber)
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
	if err := instances.Cancel(r.Context(), instanceId, opNumber); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Controller) exchangeStdio(w http.ResponseWriter, r *http.Request) {
	secretId := r.PathValue("secretId")
	instanceId := r.PathValue("instanceId")
	opNumber, err := parsePath(r, "opNumber", strconv.Atoi)
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

	var req ExchangeIORequest
	if err := readBody(r, &req); err != nil {
		writeError(w, err)
		return
	}

	maxBytes, err := parseQueryInt(r, "maxBytes", int64(s.maxBytes))
	if err != nil {
		writeError(w, err)
		return
	}
	if maxBytes <= 0 {
		maxBytes = int64(s.maxBytes)
	}
	maxWait, err := parseQuery(r, "maxWait", time.ParseDuration, DefaultMaxPollDuration)
	if err != nil {
		writeError(w, err)
		return
	}

	var resp ExchangeIOResponse

	if req.Stdin != nil {
		if len(req.Stdin.Bytes) > 0 {
			if err := validateStdinChunk(req.Stdin.Index, req.Stdin.Bytes, maxBytes); err != nil {
				writeError(w, err)
				return
			}
			if _, err := op.Stdin.AsyncWriter().WriteAt(req.Stdin.Bytes, req.Stdin.Index); err != nil {
				writeError(w, NewErrorResponse(http.StatusInternalServerError, err))
				return
			}
		}
		if req.Stdin.Closed {
			_ = op.Stdin.Close()
		}
		resp.Stdin = &ExchangeIndex{Index: req.Stdin.Index + int64(len(req.Stdin.Bytes))}
		// Return promptly after stdin is delivered so the client can read more input.
		maxWait = 0
	}

	ctx, cancel := context.WithTimeout(r.Context(), maxWait)
	defer cancel()

	var stdoutFrom int64
	if req.Stdout != nil {
		stdoutFrom = req.Stdout.Index
	}
	stdout, err := readStreamChunk(ctx, op.Stdout, stdoutFrom, maxBytes)
	if err != nil {
		writeError(w, err)
		return
	}
	resp.Stdout = exchangeStreamOut(stdoutFrom, stdout)
	var stderrFrom int64
	if req.Stderr != nil {
		stderrFrom = req.Stderr.Index
	}
	chunk, err := readStreamChunk(ctx, op.Stderr, stderrFrom, maxBytes)
	if err != nil {
		writeError(w, err)
		return
	}
	resp.Stderr = exchangeStreamOut(stderrFrom, chunk)

	if code := op.processExitCode(); code != nil {
		resp.ExitCode = code
	}

	writeResult(w, resp, http.StatusOK)
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
