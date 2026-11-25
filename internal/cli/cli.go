package cli

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
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
	Address         string          `short:"a" env:"CLIENT_ADDRESS" help:"Unix socket path, unix:// URL, http(s):// URL, or ssh://[user@]host[:port][/socket]. URL /socket is dial-stdio -s only when sshd runs the client-requested command; with restrict,command=, -s/-u/-H come from that command."`
	MaxReasonLength int             `short:"R" env:"MAX_REASON_LENGTH" default:"4096" help:"Max length of audit reason strings"`
	Debug           bool            `short:"d" env:"DEBUG" help:"Enable debug logging"`
	Pretty          bool            `short:"p" env:"PRETTY" help:"Pretty-print JSON output"`
	Secrets         Secrets         `cmd:"" help:"List secrets"`
	Secret          Secret          `cmd:"" help:"Show a secret"`
	Instances       Instances       `cmd:"" help:"List instances of a secret"`
	Instance        Instance        `cmd:"" help:"Show an instance of a secret"`
	Active          Secret          `cmd:"" help:"Show the active instance of a secret"`
	Create          SecretCommand   `cmd:"" help:"Create an instance of a secret"`
	Destroy         InstanceCommand `cmd:"" help:"Destroy an instance of a secret"`
	Activate        InstanceCommand `cmd:"" help:"Activate an instance of a secret"`
	Deactivate      InstanceCommand `cmd:"" help:"Deactivate an instance of a secret"`
	Test            InstanceCommand `cmd:"" help:"Test an instance of a secret"`
	Serve           Serve           `cmd:"" help:"Serve the secret agent API"`
	DialStdio       DialStdio       `cmd:"" name:"dial-stdio" help:"Proxy stdio to the agent Unix socket. Should not be invoked manually."`
	ctx             kongContext
	agent           backend.Backend
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

	if c.ctx.Command() == "dial-stdio" {
		return &c
	}

	var err error
	c.agent, err = NewBackend(ctx, c.Address, c.SecretsFile, c.DbFile, c.Debug, c.MaxReasonLength)
	c.ctx.FatalIfErrorf(err)
	return &c
}

func (c *CLI) Run(ctx context.Context) error {
	if c.ctx.Command() == "dial-stdio" {
		return runDialStdio(c.DialStdio.Socket, c.DialStdio.User, c.DialStdio.Header, os.Stdin, os.Stdout)
	}

	// Scripts run in their own session, so the terminal's Ctrl-C does not reach them.
	// Cancelling the context is what stops them. Restore any raw terminal before a
	// second signal kills this process.
	var broker *command.Broker
	closeBroker := func() { broker.Close() }
	var result any
	var err error
	// The closure reads broker when the signal arrives. It is still nil here.
	ctx, stop := interruptContext(ctx, closeBroker)
	defer stop()
	defer closeBroker()

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
	case "create <secret-id>":
		broker, result, err = operate(func(groups command.FileGroups) (*secrets.Instance, error) {
			return ops.Create(ctx, c.agent.Runner(c.Create.SecretID), c.Create.parameters(), noopProposer{}, groups)
		})
	case "destroy <secret-id> <instance-id>":
		broker, result, err = operate(func(groups command.FileGroups) (*secrets.Instance, error) {
			return ops.Destroy(ctx, c.agent.Runner(c.Destroy.SecretID), c.Destroy.InstanceID, c.Destroy.parameters(), noopProposer{}, groups)
		})
	case "activate <secret-id> <instance-id>":
		broker, result, err = operate(func(groups command.FileGroups) (*secrets.Instance, error) {
			return ops.Activate(ctx, c.agent.Runner(c.Activate.SecretID), c.Activate.InstanceID, c.Activate.parameters(), noopProposer{}, groups)
		})
	case "deactivate <secret-id> <instance-id>":
		broker, result, err = operate(func(groups command.FileGroups) (*secrets.Instance, error) {
			return ops.Deactivate(ctx, c.agent.Runner(c.Deactivate.SecretID), c.Deactivate.InstanceID, c.Deactivate.parameters(), noopProposer{}, groups)
		})
	case "test <secret-id> <instance-id>":
		broker, result, err = operate(func(groups command.FileGroups) (*secrets.Instance, error) {
			return ops.Test(ctx, c.agent.Runner(c.Test.SecretID), c.Test.InstanceID, c.Test.parameters(), noopProposer{}, groups)
		})
	case "serve":
		// Serve does not observe ctx. Restore default signal handling so SIGTERM stops it.
		stop()
		permissionsConfig, err := server.LoadPermissions(c.PermissionsFile)
		if err != nil {
			return err
		}
		config := server.ServerConfig{
			Socket:               c.Serve.ServerSocket,
			RequestLimit:         c.Serve.RequestLimit,
			RequestWindow:        c.Serve.RequestWindow,
			PendingOperationTTL:  c.Serve.PendingOperationTTL,
			FinishedOperationTTL: c.Serve.FinishedOperationTTL,
		}
		server := server.New(config, c.agent, permissionsConfig)
		return server.Serve()
	default:
		panic(fmt.Errorf("unknown command: %s", c.ctx.Command()))
	}

	closeBroker()
	if err != nil {
		return err
	}

	var bytes []byte
	if c.Pretty {
		bytes, err = marshal.JSONIndent(result)
	} else {
		bytes, err = marshal.JSON(result)
	}
	if err != nil {
		return err
	}

	_, err = os.Stdout.Write(bytes)
	return err
}

// operate opens the broker and runs one operation on its file groups.
// The broker is returned so the caller can restore the terminal.
func operate(op func(command.FileGroups) (*secrets.Instance, error)) (*command.Broker, *secrets.Instance, error) {
	broker, err := command.OpenBroker([]*os.File{os.Stdin, os.Stdout, os.Stderr})
	if err != nil {
		return nil, nil, err
	}
	instance, err := op(broker.Groups)
	return broker, instance, err
}

type noopProposer struct{}

func (noopProposer) Propose(context.Context, string, secrets.OperationName, executor.OperationParameters, io.ReadWriteCloser) error {
	return nil
}

// interruptContext is cancelled by SIGINT, SIGTERM, SIGHUP, or SIGQUIT.
// The first signal cancels. A second restores the terminal, then raises
// the default action, so a stuck cancel cannot trap the operator.
func interruptContext(parent context.Context, restore func()) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	go func() {
		n := 0
		for sig := range ch {
			n++
			if n == 1 {
				cancel()
				continue
			}
			if restore != nil {
				restore()
			}
			signal.Stop(ch)
			signal.Reset(sig)
			if s, ok := sig.(syscall.Signal); ok {
				_ = syscall.Kill(os.Getpid(), s)
			}
			return
		}
	}()
	return ctx, func() {
		signal.Stop(ch)
		cancel()
	}
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
	ServerSocket         string        `short:"s" help:"Unix socket path for serving the HTTP API"`
	RequestLimit         uint32        `short:"L" default:"100" help:"Maximum number of requests per request window"`
	RequestWindow        time.Duration `short:"W" default:"1m" help:"Window of time over which the request limit is enforced"`
	PendingOperationTTL  time.Duration `default:"10m" help:"How long an unstarted operation stays readable"`
	FinishedOperationTTL time.Duration `default:"2m" help:"How long a finished operation stays readable"`
}

type DialStdio struct {
	Socket string `short:"s" help:"Unix socket path (default: Nix systemd socket). With restrict,command=, set here, not in the client's ssh:// URL."`
	User   string `short:"u" help:"Name to put in the assert header; omit for the socket credential"`
	Header string `short:"H" help:"Header set with -u (default X-Secret-Agent-User); must match that assert authenticator's header"`
}
