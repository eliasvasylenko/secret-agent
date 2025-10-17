package main

import (
	"context"
	"encoding/json"
	"log"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/secret"
	"github.com/eliasvasylenko/secret-agent/internal/store"
)

func main() {
	ctx := context.Background()

	var socket string
	socketFlag := &cli.StringFlag{Name: "socket", Aliases: []string{"s"}, Destination: &socket, Sources: cli.EnvVars("SOCKET")}

	var secretsFile string
	secretsFileFlag := &cli.StringFlag{Name: "secrets-file", Aliases: []string{"S"}, Destination: &secretsFile, Sources: cli.EnvVars("SECRETS_FILE")}

	var dbFile string
	dbFileFlag := &cli.StringFlag{Name: "db-file", Aliases: []string{"b"}, Destination: &dbFile, DefaultText: "./secrets.db"}

	var secretId string
	secretArgument := &cli.StringArg{Name: "secret", Destination: &secretId}

	var instanceId string
	instanceArgument := &cli.StringArg{Name: "instance", Destination: &instanceId}

	var debug bool
	debugFlag := &cli.BoolFlag{Name: "debug", Aliases: []string{"d"}, Destination: &debug, Required: false}

	var force bool
	forceFlag := &cli.BoolFlag{Name: "force", Aliases: []string{"f"}, Destination: &force, Required: false}

	var reason string
	reasonFlag := &cli.StringFlag{Name: "reason", Aliases: []string{"r"}, Destination: &reason, Required: false}

	var pretty bool
	prettyFlag := &cli.BoolFlag{Name: "pretty", Aliases: []string{"p"}, Destination: &pretty, Required: false, Value: true}

	var from int
	fromFlag := &cli.IntFlag{Name: "from", Aliases: []string{"F"}, Destination: &from, Required: false, Value: 0}

	var to int
	toFlag := &cli.IntFlag{Name: "to", Aliases: []string{"T"}, Destination: &to, Required: false, Value: 10}

	show := func(output any) error {
		var bytes []byte
		var err error
		if pretty {
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

	parameters := func() secret.OperationParameters {
		return secret.OperationParameters{
			Env:       command.NewEnvironment().Load(os.Environ()),
			Forced:    force,
			Reason:    reason,
			StartedBy: "user",
		}
	}

	newSecretStore := func() (store.Secrets, error) {
		return store.New(ctx, store.Config{
			Socket:      socket,
			SecretsFile: secretsFile,
			DbFile:      dbFile,
			Debug:       debug,
		})
	}

	newInstanceStore := func() (store.Instances, error) {
		secretStore, err := newSecretStore()
		if err != nil {
			return nil, err
		}
		return secretStore.Instances(secretId), nil
	}

	cmd := &cli.Command{
		Usage:           "An agent to manage secrets",
		HideHelpCommand: true,
		Flags:           []cli.Flag{socketFlag, secretsFileFlag, dbFileFlag, debugFlag, prettyFlag},
		Commands: []*cli.Command{
			{
				Name:            "list",
				Usage:           "List secrets",
				HideHelpCommand: true,
				Flags:           []cli.Flag{},
				Action: func(ctx context.Context, c *cli.Command) error {
					secretStore, err := newSecretStore()
					if err != nil {
						return err
					}
					secrets, err := secretStore.List(ctx)
					if err != nil {
						return err
					}
					return show(secrets)
				},
			},
			{
				Name:            "show",
				Usage:           "Show a secret",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument},
				Flags:           []cli.Flag{},
				Action: func(ctx context.Context, c *cli.Command) error {
					secretStore, err := newSecretStore()
					if err != nil {
						return err
					}
					secret, err := secretStore.Get(ctx, secretId)
					if err != nil {
						return err
					}
					return show(secret)
				},
			},
			{
				Name:            "active",
				Usage:           "Show active secret instance",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument},
				Flags:           []cli.Flag{},
				Action: func(ctx context.Context, c *cli.Command) error {
					secretStore, err := newSecretStore()
					if err != nil {
						return err
					}
					secret, err := secretStore.GetActive(ctx, secretId)
					if err != nil {
						return err
					}
					return show(secret)
				},
			},
			{
				Name:            "history",
				Usage:           "Show operation history",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument},
				Flags:           []cli.Flag{fromFlag, toFlag},
				Action: func(ctx context.Context, c *cli.Command) error {
					secretStore, err := newSecretStore()
					if err != nil {
						return err
					}
					secret, err := secretStore.History(ctx, secretId, from, to)
					if err != nil {
						return err
					}
					return show(secret)
				},
			},
			{
				Name:            "create",
				Usage:           "Create a secret instance",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument},
				Flags:           []cli.Flag{forceFlag, reasonFlag},
				Action: func(ctx context.Context, c *cli.Command) error {
					instanceStore, err := newInstanceStore()
					if err != nil {
						return err
					}
					instance, err := instanceStore.Create(ctx, parameters())
					if err != nil {
						return err
					}
					return show(instance)
				},
			},
			{
				Name:            "destroy",
				Usage:           "Destroy a secret instance",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument, instanceArgument},
				Flags:           []cli.Flag{forceFlag, reasonFlag},
				Action: func(ctx context.Context, c *cli.Command) error {
					instanceStore, err := newInstanceStore()
					if err != nil {
						return err
					}
					instance, err := instanceStore.Destroy(ctx, instanceId, parameters())
					if err != nil {
						return err
					}
					return show(instance)
				},
			},
			{
				Name:            "activate",
				Usage:           "Activate a secret instance",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument, instanceArgument},
				Flags:           []cli.Flag{forceFlag, reasonFlag},
				Action: func(ctx context.Context, c *cli.Command) error {
					instanceStore, err := newInstanceStore()
					if err != nil {
						return err
					}
					instance, err := instanceStore.Activate(ctx, instanceId, parameters())
					if err != nil {
						return err
					}
					return show(instance)
				},
			},
			{
				Name:            "deactivate",
				Usage:           "Deactivate a secret instance",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument, instanceArgument},
				Flags:           []cli.Flag{forceFlag, reasonFlag},
				Action: func(ctx context.Context, c *cli.Command) error {
					instanceStore, err := newInstanceStore()
					if err != nil {
						return err
					}
					instance, err := instanceStore.Deactivate(ctx, instanceId, parameters())
					if err != nil {
						return err
					}
					return show(instance)
				},
			},
			{
				Name:            "test",
				Usage:           "Test an active secret instance",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument, instanceArgument},
				Flags:           []cli.Flag{forceFlag, reasonFlag},
				Action: func(ctx context.Context, c *cli.Command) error {
					instanceStore, err := newInstanceStore()
					if err != nil {
						return err
					}
					instance, err := instanceStore.Test(ctx, instanceId, parameters())
					if err != nil {
						return err
					}
					return show(instance)
				},
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
