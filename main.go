package main

import (
	"context"

	"github.com/eliasvasylenko/secret-agent/internal/cli"
)

func main() {
	ctx := context.Background()
	cli := cli.NewCLI(ctx)
	cli.Run(ctx)
}
