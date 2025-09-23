package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/DataDog/go-attestations-verifier/internal/httputil"
	"github.com/DataDog/go-attestations-verifier/pkg/rubygems"
	"github.com/spf13/cobra"
)

func rubygemsCmd() *cobra.Command {
	var name, version string

	cmd := &cobra.Command{
		Use:   "rubygems",
		Short: "Check attestations for a RubyGems package's version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			rubygemsClient := &rubygems.Client{HTTP: httputil.DefaultClient()}

			gem, err := rubygemsClient.GetGemVersion(cmd.Context(), name, version)
			if err != nil {
				return fmt.Errorf("failed to get RubyGems gem version: %w", err)
			}

			verifier, err := rubygems.NewVerifier(rubygemsClient)
			if err != nil {
				return fmt.Errorf("failed to create RubyGems verifier: %w", err)
			}

			status, err := verifier.Verify(cmd.Context(), gem)
			if err != nil {
				return fmt.Errorf("failed to verify RubyGems package: %w", err)
			}

			fmt.Fprintf(os.Stdout, "⏳ Verifying file %s (SHA256: %s)\n", status.URL, status.SHA256)

			if !status.HasAttestation {
				fmt.Fprintln(os.Stdout, "❌ No attestations found")

				return nil
			}

			if status.InferredIssuer == "" {
				fmt.Fprintln(os.Stdout, "❌ Could not infer a certificate issuer. Dangerously defaulting to skip identity checks.")
			} else {
				fmt.Fprintf(os.Stdout, "⚠️ Inferred certificate issuer %q\n", status.InferredIssuer)
			}

			if status.Error != nil {
				fmt.Fprintf(os.Stdout, "❌ Error verifying RubyGems's attestation: %s\n", status.Error)
			} else {
				fmt.Fprintln(os.Stdout, "✅ Verified RubyGems's signature with RubyGems public keys:")

				out, err := json.MarshalIndent(status.Attestation, "", "\t")
				if err != nil {
					return fmt.Errorf("marshalling RubyGems's attestation: %w", err)
				}

				fmt.Fprintln(os.Stdout, string(out))
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "name of a RubyGems project to verify")
	cmd.Flags().StringVar(&version, "version", "", "version of a RubyGems project to verify")

	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("version")

	return cmd
}
