package main

import "github.com/spf13/cobra"

const app = "go-attestations-verifier"

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{Use: app}

	cmd.AddCommand(
		versionCmd(),
		npmCmd(),
		pypiCmd(),
	)

	return cmd
}
