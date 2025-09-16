package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "dev"

func versionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "print this program's version and exit",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Fprintf(os.Stdout, "%s: %s\n", app, version)
		},
	}

	return cmd
}
