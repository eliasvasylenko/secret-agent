package main

import (
	"context"
	"log"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/eliasvasylenko/secret-agent/internal/pebble"
	"github.com/eliasvasylenko/secret-agent/internal/secret"
)

func main() {
	var plansFile string
	plansFileFlag := &cli.StringFlag{Name: "plans-file", Aliases: []string{"p"}, Destination: &plansFile, Required: true}

	var name string
	secretArgument := &cli.StringArg{Name: "secret", Destination: &name}

	store := pebble.NewStore()

	cmd := &cli.Command{
		Usage:           "An agent to manage secrets",
		HideHelpCommand: true,
		Commands: []*cli.Command{
			{
				Name:            "list",
				Usage:           "List secrets",
				HideHelpCommand: true,
				Flags:           []cli.Flag{plansFileFlag},
				Action: func(ctx context.Context, c *cli.Command) error {
					secrets, err := secret.LoadAll(plansFile, store)
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
				Flags:           []cli.Flag{plansFileFlag},
				Action: func(ctx context.Context, c *cli.Command) error {
					secret, err := secret.Load(plansFile, name, store)
					if err != nil {
						return err
					}
					return secret.Show()
				},
			},
			{
				Name:            "rotate",
				Usage:           "Rotate a secret",
				HideHelpCommand: true,
				Arguments:       []cli.Argument{secretArgument},
				Flags:           []cli.Flag{plansFileFlag},
				Action: func(ctx context.Context, c *cli.Command) error {
					secret, err := secret.Load(plansFile, name, store)
					if err != nil {
						return err
					}
					return secret.Rotate()
				},
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
