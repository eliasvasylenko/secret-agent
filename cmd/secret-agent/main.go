package main

import (
	"context"
	"log"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/eliasvasylenko/secret-agent/internal/server"
	"github.com/eliasvasylenko/secret-agent/internal/store"
)

func main() {
	ctx := context.Background()

	var secretsFile string
	secretsFileFlag := &cli.StringFlag{Name: "secrets-file", Aliases: []string{"s"}, Destination: &secretsFile, Sources: cli.EnvVars("SECRETS_FILE")}

	var debug bool
	debugFlag := &cli.BoolFlag{Name: "debug", Aliases: []string{"d"}, Destination: &debug, Required: false}

	var socket string
	socketFlag := &cli.StringFlag{Name: "socket", Aliases: []string{"S"}, Destination: &socket, Sources: cli.EnvVars("SOCKET")}

	newSecretStore := func() (store.Secrets, error) {
		return store.New(ctx, store.Config{
			Socket:      socket,
			SecretsFile: secretsFile,
			Debug:       debug,
		})
	}

	cmd := &cli.Command{
		Usage:           "An agent to manage secrets",
		HideHelpCommand: true,
		Flags:           []cli.Flag{secretsFileFlag, debugFlag, socketFlag},
		Action: func(ctx context.Context, c *cli.Command) error {
			secretStore, err := newSecretStore()
			if err != nil {
				return err
			}
			server, err := server.New(socket, secretStore, debug)
			if err != nil {
				return err
			}
			return server.Serve()
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
