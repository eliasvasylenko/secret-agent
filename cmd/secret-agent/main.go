package main

import (
	"context"
	"log"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/eliasvasylenko/secret-agent/internal/server"
)

func main() {
	var plansFile string
	plansFileFlag := &cli.StringFlag{Name: "plans-file", Aliases: []string{"p"}, Destination: &plansFile, Sources: cli.EnvVars("PLANS_FILE")}

	var debug bool
	debugFlag := &cli.BoolFlag{Name: "debug", Aliases: []string{"d"}, Destination: &debug, Required: false}

	var socket string
	socketFlag := &cli.StringFlag{Name: "socket", Aliases: []string{"s"}, Destination: &socket, Sources: cli.EnvVars("SOCKET")}

	cmd := &cli.Command{
		Usage:           "An agent to manage secrets",
		HideHelpCommand: true,
		Flags:           []cli.Flag{plansFileFlag, debugFlag, socketFlag},
		Action: func(ctx context.Context, c *cli.Command) error {
			server, err := server.New(socket, plansFile, debug)
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
