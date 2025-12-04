package main

import (
	"context"
	"log"
	"os"

	"github.com/alecthomas/kong"
	"github.com/eliasvasylenko/secret-agent/internal/cli"
	com "github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/marshal"
	sec "github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/eliasvasylenko/secret-agent/internal/server"
	ser "github.com/eliasvasylenko/secret-agent/internal/server"
	"github.com/eliasvasylenko/secret-agent/internal/store"
)

func main() {
	ctx := context.Background()
	cli := NewCLI(ctx)
	cli.Run(ctx)
}

type CLI struct {
	SecretsFile     string          `short:"S" env:"SECRETS_FILE"`
	PermissionsFile string          `short:"P" env:"PERMISSIONS_FILE"`
	DbFile          string          `short:"D" env:"DB_FILE"`
	ClientSocket    string          `short:"c" env:"CLIENT_SOCKET"`
	Debug           bool            `short:"d" env:"DEBUG"`
	Pretty          bool            `short:"p" env:"PRETTY"`
	Secrets         Secrets         `cmd:"" help:"List secrets"`
	Secret          Secret          `cmd:"" help:"Show a secret"`
	Instances       Instances       `cmd:"" help:"List instances of a secret"`
	Instance        Instance        `cmd:"" help:"Show an instance of a secret"`
	Active          Secret          `cmd:"" help:"Show the active instance of a secret"`
	History         History         `cmd:"" help:"Show the operation history of a secret"`
	Create          SecretCommand   `cmd:"" help:"Create an instance of a secret"`
	Destroy         InstanceCommand `cmd:"" help:"Destroy an instance of a secret"`
	Activate        InstanceCommand `cmd:"" help:"Activate an instance of a secret"`
	Deactivate      InstanceCommand `cmd:"" help:"Deactivate an instance of a secret"`
	Test            InstanceCommand `cmd:"" help:"Test an instance of a secret"`
	Serve           Serve           `cmd:"" help:"Serve the secret agent API"`

	ctx         *kong.Context
	secretStore store.Secrets
}

func NewCLI(ctx context.Context) *CLI {
	var c CLI
	c.ctx = kong.Parse(&c)

	if c.Debug {
		log.Default().Printf("cli %v", c)
	}

	var err error
	c.secretStore, err = cli.NewStore(ctx, c.ClientSocket, c.SecretsFile, c.DbFile, c.Debug)
	c.ctx.FatalIfErrorf(err)
	return &c
}

func (c *CLI) Run(ctx context.Context) {
	var result any
	var err error
	switch c.ctx.Command() {
	case "secrets":
		result, err = c.secretStore.List(ctx)
	case "secret <secret-id>":
		result, err = c.secretStore.Get(ctx, c.Secret.SecretID)
	case "instances <secret-id>":
		result, err = c.secretStore.Instances(c.Instances.SecretID).List(ctx, c.Instances.From, c.Instances.To)
	case "instance <secret-id> <instance-id>":
		result, err = c.secretStore.Instances(c.Instance.SecretID).Get(ctx, c.Instance.InstanceID)
	case "active <secret-id>":
		result, err = c.secretStore.Instances(c.Instance.SecretID).GetActive(ctx)
	case "history <secret-id>":
		result, err = c.secretStore.History(ctx, c.History.SecretID, c.History.From, c.History.To)
	case "history <secret-id> <instance-id>":
		result, err = c.secretStore.Instances(c.Instance.SecretID).History(ctx, c.Instance.InstanceID, c.History.From, c.History.To)
	case "create <secret-id>":
		result, err = c.secretStore.Instances(c.Create.SecretID).Create(ctx, c.Create.parameters())
	case "destroy <secret-id> <instance-id>":
		result, err = c.secretStore.Instances(c.Destroy.SecretID).Destroy(ctx, c.Destroy.InstanceID, c.Destroy.parameters())
	case "activate <secret-id> <instance-id>":
		result, err = c.secretStore.Instances(c.Activate.SecretID).Activate(ctx, c.Activate.InstanceID, c.Activate.parameters())
	case "deactivate <secret-id> <instance-id>":
		result, err = c.secretStore.Instances(c.Deactivate.SecretID).Deactivate(ctx, c.Deactivate.InstanceID, c.Deactivate.parameters())
	case "test <secret-id> <instance-id>":
		result, err = c.secretStore.Instances(c.Test.SecretID).Test(ctx, c.Test.InstanceID, c.Test.parameters())
	case "serve":
		permissionsConfig, err := server.LoadPermissions(c.PermissionsFile)
		c.ctx.FatalIfErrorf(err)
		server := ser.New(c.Serve.ServerSocket, c.secretStore, permissionsConfig)
		err = server.Serve()
	default:
		panic(c.ctx.Command())
	}

	c.ctx.FatalIfErrorf(err)

	var bytes []byte
	if c.Pretty {
		bytes, err = marshal.JSONIndent(result)
	} else {
		bytes, err = marshal.JSON(result)
	}
	c.ctx.FatalIfErrorf(err)

	_, err = os.Stdout.Write(bytes)

	c.ctx.FatalIfErrorf(err)
}

type Secrets struct{}

type Secret struct {
	SecretID string `arg:""`
}

type Instances struct {
	SecretID string `arg:""`
	Bounds
}

type Instance struct {
	SecretID   string `arg:""`
	InstanceID string `arg:""`
}

type History struct {
	SecretID   string `arg:""`
	InstanceID string `arg:"" optional:""`
	Bounds
}

type Bounds struct {
	From int `short:"l" default:"0"`
	To   int `short:"u" default:"10"`
}

type SecretCommand struct {
	SecretID string `arg:""`
	Command
}

type InstanceCommand struct {
	SecretID   string `arg:""`
	InstanceID string `arg:""`
	Command
}

type Command struct {
	Force  bool   `short:"f"`
	Reason string `short:"r"`
}

func (c *Command) parameters() sec.OperationParameters {
	return sec.OperationParameters{
		Env:       com.NewEnvironment().Load(os.Environ()),
		Forced:    c.Force,
		Reason:    c.Reason,
		StartedBy: "user",
	}
}

type Serve struct {
	ServerSocket string `short:"s"`
}
