package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
)

func main() {
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ %s\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	err := rootCmd().ExecuteContext(ctx)
	if err != nil {
		return fmt.Errorf("failed with error: %w", err)
	}

	return nil
}
