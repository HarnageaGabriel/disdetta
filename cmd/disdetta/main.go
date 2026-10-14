// Command disdetta finds Bitnami dependencies before migration.
package main

import (
	"context"
	"os"

	"github.com/HarnageaGabriel/disdetta/internal/cli"
)

func main() {
	os.Exit(cli.Execute(context.Background(), os.Args[1:], cli.IO{Out: os.Stdout, Err: os.Stderr}))
}
