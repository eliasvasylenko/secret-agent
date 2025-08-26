package main

import (
	"context"
	"log"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/eliasvasylenko/secret-agent/internal/secret"
	"github.com/eliasvasylenko/secret-agent/internal/sqlite"
)

func main() {
	var plansFile string
	plansFileFlag := &cli.StringFlag{Name: "plans-file", Aliases: []string{"p"}, Destination: &plansFile, Required: true}

	var name string
	secretArgument := &cli.StringArg{Name: "secret", Destination: &name}

	var id string
	instanceArgument := &cli.StringArg{Name: "instance", Destination: &id}

	var debug bool
	debugFlag := &cli.BoolFlag{Name: "debug", Aliases: []string{"d"}, Destination: &debug, Required: false}

	var force bool
	forceFlag := &cli.BoolFlag{Name: "force", Aliases: []string{"f"}, Destination: &force, Required: false}

	var pretty bool
	prettyFlag := &cli.BoolFlag{Name: "pretty", Aliases: []string{"p"}, Destination: &pretty, Required: false, Value: true}

	store := func() secret.InstanceStore {
		return sqlite.NewStore(debug)
	}

	cmd := &cli.Command{
		Usage:           "An agent to manage secrets",
		HideHelpCommand: true,
		Flags:           []cli.Flag{debugFlag},
		Commands: []*cli.Command{
			{
				Name:            "list",
				Usage:           "List secrets",
				HideHelpCommand: true,
				Flags:           []cli.Flag{plansFileFlag},
				Action: func(ctx context.Context, c *cli.Command) error {
					secrets, err := secret.LoadAll(plansFile, store())
					if err != nil {
						return err
					}
					return secrets.List()
				},
			},
			{
				Name:            "show",
				Usage:           "Show a secret",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument},
				Flags:           []cli.Flag{plansFileFlag, prettyFlag},
				Action: func(ctx context.Context, c *cli.Command) error {
					secret, err := secret.Load(plansFile, name, store())
					if err != nil {
						return err
					}
					return secret.Show(pretty)
				},
			},
			{
				Name:            "create",
				Usage:           "Create a secret instance",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument},
				Flags:           []cli.Flag{plansFileFlag, prettyFlag},
				Action: func(ctx context.Context, c *cli.Command) error {
					secret, err := secret.Load(plansFile, name, store())
					if err != nil {
						return err
					}
					instance, err := secret.CreateInstance()
					if err != nil {
						return err
					}
					return instance.Show(pretty)
				},
			},
			{
				Name:            "destroy",
				Usage:           "Destroy a secret instance",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument, instanceArgument},
				Flags:           []cli.Flag{plansFileFlag, forceFlag},
				Action: func(ctx context.Context, c *cli.Command) error {
					secret, err := secret.Load(plansFile, name, store())
					if err != nil {
						return err
					}
					instance, err := secret.GetInstance(id)
					if err != nil {
						return err
					}
					return instance.Destroy(force)
				},
			},
			{
				Name:            "activate",
				Usage:           "Activate a secret instance",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument, instanceArgument},
				Flags:           []cli.Flag{plansFileFlag, prettyFlag, forceFlag},
				Action: func(ctx context.Context, c *cli.Command) error {
					secret, err := secret.Load(plansFile, name, store())
					if err != nil {
						return err
					}
					instance, err := secret.GetInstance(id)
					if err != nil {
						return err
					}
					err = instance.Activate(force)
					if err != nil {
						return err
					}
					return instance.Show(pretty)
				},
			},
			{
				Name:            "deactivate",
				Usage:           "Deactivate a secret instance",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument, instanceArgument},
				Flags:           []cli.Flag{plansFileFlag, prettyFlag, forceFlag},
				Action: func(ctx context.Context, c *cli.Command) error {
					secret, err := secret.Load(plansFile, name, store())
					if err != nil {
						return err
					}
					instance, err := secret.GetInstance(id)
					if err != nil {
						return err
					}
					err = instance.Deactivate(force)
					if err != nil {
						return err
					}
					return instance.Show(pretty)
				},
			},
			{
				Name:            "test",
				Usage:           "Test an active secret instance",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument, instanceArgument},
				Flags:           []cli.Flag{plansFileFlag, prettyFlag, forceFlag},
				Action: func(ctx context.Context, c *cli.Command) error {
					secret, err := secret.Load(plansFile, name, store())
					if err != nil {
						return err
					}
					instance, err := secret.GetInstance(id)
					if err != nil {
						return err
					}
					err = instance.Test(force)
					if err != nil {
						return err
					}
					return instance.Show(pretty)
				},
			},
			{
				Name:            "rotate",
				Usage:           "Rotate a secret",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument},
				Flags:           []cli.Flag{plansFileFlag, prettyFlag, forceFlag},
				Action: func(ctx context.Context, c *cli.Command) error {
					secret, err := secret.Load(plansFile, name, store())
					if err != nil {
						return err
					}
					err = secret.Rotate(force)
					if err != nil {
						return err
					}
					return secret.Show(pretty)
				},
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
