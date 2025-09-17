package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/DataDog/go-attestations-verifier/internal/httputil"
	"github.com/DataDog/go-attestations-verifier/pkg/npm"
	"github.com/spf13/cobra"
)

//nolint:funlen
func npmCmd() *cobra.Command {
	var name, version string

	cmd := &cobra.Command{
		Use:   "npm",
		Short: "Check attestations for a NPM package's version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			npmClient := &npm.Client{HTTP: httputil.DefaultClient()}

			pkg, err := npmClient.GetPackageVersion(cmd.Context(), name, version)
			if err != nil {
				return fmt.Errorf("failed to get NPM package version: %w", err)
			}

			verifier, err := npm.NewVerifier(cmd.Context(), npmClient)
			if err != nil {
				return fmt.Errorf("failed to create NPM verifier: %w", err)
			}

			status, err := verifier.Verify(cmd.Context(), pkg)
			if err != nil {
				return fmt.Errorf("failed to verify NPM package: %w", err)
			}

			fmt.Fprintf(os.Stdout, "⏳ Verifying file %s (SHA512: %s)\n", status.URL, status.SHA512)

			if !status.HasAttestations {
				fmt.Fprintln(os.Stdout, "❌ No attestations found")

				return nil
			}

			if status.AttestationError != nil {
				fmt.Fprintf(os.Stdout, "❌ Error verifying NPM's attestation: %s\n", status.AttestationError)
			} else {
				fmt.Fprintln(os.Stdout, "✅ Verified NPM's signature with NPM public keys:")

				out, err := json.MarshalIndent(status.Attestation, "", "\t")
				if err != nil {
					return fmt.Errorf("marshalling NPM's attestation: %w", err)
				}

				fmt.Fprintln(os.Stdout, string(out))
			}

			if status.InferredIssuer == "" {
				fmt.Fprintln(os.Stdout, "❌ Could not infer a certificate issuer. Dangerously defaulting to skip identity checks.")
			} else {
				fmt.Fprintf(os.Stdout, "⚠️ Inferred certificate issuer %q\n", status.InferredIssuer)
			}

			if status.ProvenanceError != nil {
				fmt.Fprintf(os.Stdout, "❌ Error verifying SigStore's provenance: %s\n", status.ProvenanceError)
			} else {
				fmt.Fprintln(os.Stdout, "✅ Verified SigStore's provenance:")

				out, err := json.MarshalIndent(status.Provenance, "", "\t")
				if err != nil {
					return fmt.Errorf("marshalling SigStore's provenance: %w", err)
				}

				fmt.Fprintln(os.Stdout, string(out))
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "name of a NPM package to verify")
	cmd.Flags().StringVar(&version, "version", "", "version of a NPM package to verify")

	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("version")

	return cmd
}
