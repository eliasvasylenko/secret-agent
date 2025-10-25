package main

import (
	"context"
	"encoding/json"
	"log"
	"os"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/secret"
	"github.com/eliasvasylenko/secret-agent/internal/store"
	"github.com/urfave/cli/v3"
)

func main() {
	NewCLI().run(context.Background())
}

type CLI struct {
	socket      string
	secretsFile string
	dbFile      string
	secretId    string
	instanceId  string
	debug       bool
	force       bool
	reason      string
	pretty      bool
	from        int
	to          int
	cmd         *cli.Command
}

func NewCLI() *CLI {
	c := &CLI{}

	socketFlag := &cli.StringFlag{Name: "socket", Aliases: []string{"s"}, Destination: &c.socket, Sources: cli.EnvVars("SOCKET")}
	secretsFileFlag := &cli.StringFlag{Name: "secrets-file", Aliases: []string{"S"}, Destination: &c.secretsFile, Sources: cli.EnvVars("SECRETS_FILE")}
	dbFileFlag := &cli.StringFlag{Name: "db-file", Aliases: []string{"b"}, Destination: &c.dbFile, DefaultText: "./secrets.db"}
	secretArgument := &cli.StringArg{Name: "secret", Destination: &c.secretId}
	instanceArgument := &cli.StringArg{Name: "instance", Destination: &c.instanceId}
	optionalInstanceArgument := &cli.StringArg{Name: "instance", Destination: &c.instanceId, Value: ""}
	debugFlag := &cli.BoolFlag{Name: "debug", Aliases: []string{"d"}, Destination: &c.debug}
	forceFlag := &cli.BoolFlag{Name: "force", Aliases: []string{"f"}, Destination: &c.force}
	reasonFlag := &cli.StringFlag{Name: "reason", Aliases: []string{"r"}, Destination: &c.reason}
	prettyFlag := &cli.BoolFlag{Name: "pretty", Aliases: []string{"p"}, Destination: &c.pretty, Value: true}
	fromFlag := &cli.IntFlag{Name: "from", Aliases: []string{"F"}, Destination: &c.from, Value: 0}
	toFlag := &cli.IntFlag{Name: "to", Aliases: []string{"T"}, Destination: &c.to, Value: 10}

	c.cmd = &cli.Command{
		Usage:           "An agent to manage secrets",
		HideHelpCommand: true,
		Flags:           []cli.Flag{socketFlag, secretsFileFlag, dbFileFlag, debugFlag, prettyFlag},
		Commands: []*cli.Command{
			{
				Name:            "secrets",
				Usage:           "List secrets",
				HideHelpCommand: true,
				Action: c.subCommand(func(ctx context.Context, secretStore store.Secrets, instanceStore store.Instances) (any, error) {
					return secretStore.List(ctx)
				}),
			},
			{
				Name:            "secret",
				Usage:           "Show a secret",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument},
				Action: c.subCommand(func(ctx context.Context, secretStore store.Secrets, instanceStore store.Instances) (any, error) {
					return secretStore.Get(ctx, c.secretId)
				}),
			},
			{
				Name:            "instances",
				Usage:           "List secret instances",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument},
				Flags:           []cli.Flag{fromFlag, toFlag},
				Action: c.subCommand(func(ctx context.Context, secretStore store.Secrets, instanceStore store.Instances) (any, error) {
					return instanceStore.List(ctx, c.from, c.to)
				}),
			},
			{
				Name:            "instance",
				Usage:           "Show a secret instance",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument, instanceArgument},
				Action: c.subCommand(func(ctx context.Context, secretStore store.Secrets, instanceStore store.Instances) (any, error) {
					return instanceStore.Destroy(ctx, c.instanceId, c.parameters())
				}),
			},
			{
				Name:            "active",
				Usage:           "Show the active instance of a secret",
				HideHelpCommand: true,
				Action: c.subCommand(func(ctx context.Context, secretStore store.Secrets, instanceStore store.Instances) (any, error) {
					return secretStore.GetActive(ctx, c.secretId)
				}),
			},
			{
				Name:            "history",
				Usage:           "Show the operation history of a secret",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument, optionalInstanceArgument},
				Flags:           []cli.Flag{fromFlag, toFlag},
				Action: c.subCommand(func(ctx context.Context, secretStore store.Secrets, instanceStore store.Instances) (any, error) {
					if c.instanceId == "" {
						return secretStore.History(ctx, c.secretId, c.from, c.to)
					} else {
						return instanceStore.History(ctx, c.instanceId, c.from, c.to)
					}
				}),
			},
			{
				Name:            "create",
				Usage:           "Create a secret instance",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument},
				Flags:           []cli.Flag{forceFlag, reasonFlag},
				Action: c.subCommand(func(ctx context.Context, secretStore store.Secrets, instanceStore store.Instances) (any, error) {
					return instanceStore.Create(ctx, c.parameters())
				}),
			},
			{
				Name:            "destroy",
				Usage:           "Destroy a secret instance",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument, instanceArgument},
				Flags:           []cli.Flag{forceFlag, reasonFlag},
				Action: c.subCommand(func(ctx context.Context, secretStore store.Secrets, instanceStore store.Instances) (any, error) {
					return instanceStore.Destroy(ctx, c.instanceId, c.parameters())
				}),
			},
			{
				Name:            "activate",
				Usage:           "Activate a secret instance",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument, instanceArgument},
				Flags:           []cli.Flag{forceFlag, reasonFlag},
				Action: c.subCommand(func(ctx context.Context, secretStore store.Secrets, instanceStore store.Instances) (any, error) {
					return instanceStore.Activate(ctx, c.instanceId, c.parameters())
				}),
			},
			{
				Name:            "deactivate",
				Usage:           "Deactivate a secret instance",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument, instanceArgument},
				Flags:           []cli.Flag{forceFlag, reasonFlag},
				Action: c.subCommand(func(ctx context.Context, secretStore store.Secrets, instanceStore store.Instances) (any, error) {
					return instanceStore.Deactivate(ctx, c.instanceId, c.parameters())
				}),
			},
			{
				Name:            "test",
				Usage:           "Test an active secret instance",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument, instanceArgument},
				Flags:           []cli.Flag{forceFlag, reasonFlag},
				Action: c.subCommand(func(ctx context.Context, secretStore store.Secrets, instanceStore store.Instances) (any, error) {
					return instanceStore.Test(ctx, c.instanceId, c.parameters())
				}),
			},
		},
	}
	return c
}

func (c *CLI) run(ctx context.Context) {
	if err := c.cmd.Run(ctx, os.Args); err != nil {
		log.Fatal(err)
	}
}

func (c *CLI) print(output any, err error) error {
	var bytes []byte
	if c.pretty {
		bytes, err = json.MarshalIndent(output, "", "  ")
	} else {
		bytes, err = json.Marshal(output)
	}
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(bytes)
	return err
}

func (c *CLI) parameters() secret.OperationParameters {
	return secret.OperationParameters{
		Env:       command.NewEnvironment().Load(os.Environ()),
		Forced:    c.force,
		Reason:    c.reason,
		StartedBy: "user",
	}
}

func (c *CLI) subCommand(run func(ctx context.Context, secrets store.Secrets, instances store.Instances) (any, error)) cli.ActionFunc {
	return func(ctx context.Context, _ *cli.Command) error {
		secretStore, err := store.New(ctx, store.Config{
			Socket:      c.socket,
			SecretsFile: c.secretsFile,
			DbFile:      c.dbFile,
			Debug:       c.debug,
		})
		if err != nil {
			return err
		}
		instanceStore := secretStore.Instances(c.secretId)
		result, err := run(ctx, secretStore, instanceStore)
		return c.print(result, err)
	}
}
