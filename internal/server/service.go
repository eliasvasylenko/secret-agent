package server

import (
	"context"
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

type Service struct {
	secretStore store.Secrets
}

type identityKey struct{}

func identityFromContext(ctx context.Context) *auth.Identity {
	identity, ok := ctx.Value(identityKey{}).(*auth.Identity)
	if !ok {
		return nil
	}
	return identity
}

func (s *Service) listSecrets(w http.ResponseWriter, r *http.Request) (any, int, error) {
	secs, err := s.secretStore.List(r.Context())
	if err != nil {
		return nil, 0, NewErrorResponse(http.StatusBadRequest, err)
	}
	return ItemsResponse[secrets.Secrets]{secs}, http.StatusOK, nil
}

func (s *Service) getSecret(w http.ResponseWriter, r *http.Request) (any, int, error) {
	secretId := r.PathValue("secretId")
	secret, err := s.secretStore.Get(r.Context(), secretId)
	if err != nil {
		return nil, 0, NewErrorResponse(http.StatusBadRequest, err)
	}
	return secret, http.StatusOK, nil
}

func (s *Service) listInstances(w http.ResponseWriter, r *http.Request) (any, int, error) {
	secretId := r.PathValue("secretId")
	instances := s.secretStore.Instances(secretId)
	from, to, err := parseRange(*r.URL)
	insts, err := instances.List(r.Context(), from, to)
	if err != nil {
		return nil, 0, NewErrorResponse(http.StatusBadRequest, err)
	}
	return ItemsResponse[secrets.Instances]{insts}, http.StatusOK, nil
}

func (s *Service) createInstance(w http.ResponseWriter, r *http.Request) (any, int, error) {
	secretId := r.PathValue("secretId")
	instances := s.secretStore.Instances(secretId)
	var operation OperationParameters
	err := readBody(r, &operation)
	if err != nil {
		return nil, 0, err
	}
	identity := identityFromContext(r.Context())
	if identity == nil {
		return nil, 0, NewErrorResponse(http.StatusInternalServerError, fmt.Errorf("identity not found in context"))
	}
	parameters := secrets.OperationParameters{
		Env:       operation.Env,
		Forced:    operation.Forced,
		Reason:    operation.Reason,
		StartedBy: identity.Principal,
	}
	instance, err := instances.Create(r.Context(), parameters)
	if err != nil {
		return nil, 0, err
	}
	return instance, http.StatusOK, nil
}

func (s *Service) getInstance(w http.ResponseWriter, r *http.Request) (any, int, error) {
	secretId := r.PathValue("secretId")
	instanceId := r.PathValue("instanceId")
	instances := s.secretStore.Instances(secretId)
	instance, err := instances.Get(r.Context(), instanceId)
	if err != nil {
		return nil, 0, err
	}
	return instance, http.StatusOK, nil
}

func (s *Service) getOperations(w http.ResponseWriter, r *http.Request) (any, int, error) {
	secretId := r.PathValue("secretId")
	instanceId := r.PathValue("instanceId")
	from, to, err := parseRange(*r.URL)
	instances := s.secretStore.Instances(secretId)
	operations, err := instances.History(r.Context(), instanceId, int(from), int(to))
	if err != nil {
		return nil, 0, err
	}
	return operations, http.StatusOK, nil
}

func (s *Service) createOperation(w http.ResponseWriter, r *http.Request) (any, int, error) {
	secretId := r.PathValue("secretId")
	instanceId := r.PathValue("instanceId")
	var operation CreateOperationParameters
	err := readBody(r, &operation)
	if err != nil {
		return nil, 0, err
	}

	identity := identityFromContext(r.Context())
	if identity == nil {
		return nil, 0, NewErrorResponse(http.StatusInternalServerError, fmt.Errorf("identity not found in context"))
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
		return nil, 0, NewErrorResponse(http.StatusBadRequest, fmt.Errorf("Cannot post operation %s", operation.Name))
	}
	if err != nil {
		return nil, 0, err
	}
	return instance, http.StatusOK, nil
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
