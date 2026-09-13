package cli

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/alecthomas/kong"
	"github.com/eliasvasylenko/secret-agent/internal/backend"
	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/marshal"
	"github.com/eliasvasylenko/secret-agent/internal/ops"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/eliasvasylenko/secret-agent/internal/server"
)

type CLI struct {
	SecretsFile     string          `short:"S" env:"SECRETS_FILE" help:"Path to secrets configuration file"`
	PermissionsFile string          `short:"P" env:"PERMISSIONS_FILE" help:"Path to permissions (roles/bindings) configuration file"`
	DbFile          string          `short:"D" env:"DB_FILE" help:"Path to sqlite database file"`
	Address         string          `short:"a" env:"CLIENT_ADDRESS" help:"Unix socket path, unix:// URL, or http(s) URL of a running secret-agent server"`
	MaxReasonLength int             `short:"R" env:"MAX_REASON_LENGTH" default:"4096" help:"Max length of audit reason strings"`
	Debug           bool            `short:"d" env:"DEBUG" help:"Enable debug logging"`
	Pretty          bool            `short:"p" env:"PRETTY" help:"Pretty-print JSON output"`
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

	ctx   kongContext
	agent backend.Backend
}

type kongContext interface {
	Command() string
	FatalIfErrorf(err error, args ...any)
}

func NewCLI(ctx context.Context) *CLI {
	var c CLI
	c.ctx = kong.Parse(&c)

	if c.Debug {
		log.Default().Printf("cli %v", c)
	}

	var err error
	c.agent, err = NewBackend(ctx, c.Address, c.SecretsFile, c.DbFile, c.Debug, c.MaxReasonLength)
	c.ctx.FatalIfErrorf(err)
	return &c
}

func (c *CLI) Run(ctx context.Context) {
	var result any
	var err error
	catalog := c.agent.Catalog()
	switch c.ctx.Command() {
	case "secrets":
		result, err = catalog.Secrets().List(ctx)
	case "secret <secret-id>":
		result, err = catalog.Secrets().Get(ctx, c.Secret.SecretID)
	case "instances <secret-id>":
		secretId := c.Instances.SecretID
		result, err = catalog.Instances().List(ctx, &secretId, c.Instances.From, c.Instances.To)
	case "instance <secret-id> <instance-id>":
		result, err = catalog.Instances().Get(ctx, c.Instance.InstanceID)
	case "active <secret-id>":
		result, err = catalog.Instances().GetActive(ctx, c.Active.SecretID)
	case "history <secret-id>":
		secretId := c.History.SecretID
		result, err = catalog.Operations().List(ctx, &secretId, nil, c.History.From, c.History.To)
	case "history <secret-id> <instance-id>":
		secretId := c.History.SecretID
		instanceId := c.History.InstanceID
		result, err = catalog.Operations().List(ctx, &secretId, &instanceId, c.History.From, c.History.To)
	case "create <secret-id>":
		result, err = ops.Create(ctx, c.agent.Runner(c.Create.SecretID), c.Create.parameters(), noopProposer{}, c.stdio())
	case "destroy <secret-id> <instance-id>":
		result, err = ops.Destroy(ctx, c.agent.Runner(c.Destroy.SecretID), c.Destroy.InstanceID, c.Destroy.parameters(), noopProposer{}, c.stdio())
	case "activate <secret-id> <instance-id>":
		result, err = ops.Activate(ctx, c.agent.Runner(c.Activate.SecretID), c.Activate.InstanceID, c.Activate.parameters(), noopProposer{}, c.stdio())
	case "deactivate <secret-id> <instance-id>":
		result, err = ops.Deactivate(ctx, c.agent.Runner(c.Deactivate.SecretID), c.Deactivate.InstanceID, c.Deactivate.parameters(), noopProposer{}, c.stdio())
	case "test <secret-id> <instance-id>":
		result, err = ops.Test(ctx, c.agent.Runner(c.Test.SecretID), c.Test.InstanceID, c.Test.parameters(), noopProposer{}, c.stdio())
	case "serve":
		permissionsConfig, err := server.LoadPermissions(c.PermissionsFile)
		c.ctx.FatalIfErrorf(err)
		config := server.ServerConfig{
			Socket:        c.Serve.ServerSocket,
			RequestLimit:  c.Serve.RequestLimit,
			RequestWindow: c.Serve.RequestWindow,
			OutputTTL:     c.Serve.OutputTTL,
		}
		server := server.New(config, c.agent, permissionsConfig)
		err = server.Serve()
	default:
		panic(fmt.Errorf("unknown command: %s", c.ctx.Command()))
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

type noopProposer struct{}

func (noopProposer) Propose(context.Context, secrets.OperationName, executor.OperationParameters) error {
	return nil
}

func (c *CLI) stdio() command.Stdio {
	return command.Stdio{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
}

type Secrets struct{}

type Secret struct {
	SecretID string `arg:"" help:"ID of the secret"`
}

type Instances struct {
	SecretID string `arg:"" help:"ID of the secret"`
	Bounds
}

type Instance struct {
	SecretID   string `arg:"" help:"ID of the secret"`
	InstanceID string `arg:"" help:"ID of the instance"`
}

type History struct {
	SecretID   string `arg:"" help:"ID of the secret"`
	InstanceID string `arg:"" optional:"" help:"Optional ID of the instance"`
	Bounds
}

type Bounds struct {
	From int `short:"l" default:"0" help:"Lower bound (inclusive) for collection listing"`
	To   int `short:"u" default:"10" help:"Upper bound (exclusive) for collection listing"`
}

type SecretCommand struct {
	SecretID string `arg:"" help:"ID of the secret"`
	Command
}

type InstanceCommand struct {
	SecretCommand
	InstanceID string `arg:"" help:"ID of the instance"`
}

type Command struct {
	Force  bool   `short:"f" help:"Force the operation, overriding safety checks where allowed"`
	Reason string `short:"r" help:"Audit reason for the operation"`
}

func (c *Command) parameters() executor.OperationParameters {
	return executor.OperationParameters{
		Env:       command.NewEnvironment().Load(os.Environ()),
		Forced:    c.Force,
		Reason:    c.Reason,
		StartedBy: "user",
	}
}

type Serve struct {
	ServerSocket  string        `short:"s" help:"Unix socket path for serving the HTTP API"`
	RequestLimit  uint32        `short:"L" default:"100" help:"Maximum number of requests per request window"`
	RequestWindow time.Duration `short:"W" default:"1m" help:"Window of time over which the request limit is enforced"`
	OutputTTL     time.Duration `short:"T" default:"5m" help:"Reserved: future orphan attach-slot timeout (unused)"`
}
