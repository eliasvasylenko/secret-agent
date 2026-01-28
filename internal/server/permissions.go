package server

import (
	"encoding/json"
	"io"
	"os"

	"github.com/eliasvasylenko/secret-agent/internal/auth"
)

type Permissions struct {
	Roles  auth.Roles  `json:"roles"`
	Claims auth.Claims `json:"claims"`
}

func LoadPermissions(permissionsFileName string) (*Permissions, error) {
	permissionsFile, err := os.Open(permissionsFileName)
	if err != nil {
		return &Permissions{}, err
	}

	permissionsBytes, err := io.ReadAll(permissionsFile)
	if err != nil {
		return &Permissions{}, err
	}

	var permissions Permissions
	err = json.Unmarshal(permissionsBytes, &permissions)

	return &permissions, err
}
