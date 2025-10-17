package secret

import (
	"github.com/eliasvasylenko/secret-agent/internal/command"
)

// The status of a secret instance at a point in time
type Operation struct {
	Id         int    `json:"id"`
	SecretId   string `json:"secretId"`
	InstanceId string `json:"instanceId"`
	Status     `json:""`
}

type OperationParameters struct {
	Env       command.Environment `json:"env"`
	Forced    bool                `json:"forced"`
	Reason    string              `json:"reason"`
	StartedBy string              `json:"startedBy"`
}

// An operation which may be performed on a secret instance
type OperationName string

const (
	Create     OperationName = "create"
	Destroy    OperationName = "destroy"
	Activate   OperationName = "activate"
	Deactivate OperationName = "deactivate"
	Test       OperationName = "test"
)
