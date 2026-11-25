package main

import (
	"context"
	"fmt"
	"os"

	"github.com/eliasvasylenko/secret-agent/internal/cli"
)

func main() {
	ctx := context.Background()
	c := cli.NewCLI(ctx)
	if err := c.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
