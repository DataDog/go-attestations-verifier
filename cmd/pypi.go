package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/DataDog/go-attestations-verifier/internal/httputil"
	"github.com/DataDog/go-attestations-verifier/pkg/pypi"
	"github.com/spf13/cobra"
)

//nolint:funlen
func pypiCmd() *cobra.Command {
	var name, version string

	cmd := &cobra.Command{
		Use:   "pypi",
		Short: "Check attestations for a PyPI package's version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			pypiClient := &pypi.Client{HTTP: httputil.DefaultClient()}

			project, err := pypiClient.GetProject(cmd.Context(), name)
			if err != nil {
				return fmt.Errorf("failed to get PyPI project: %w", err)
			}

			verifier, err := pypi.NewVerifier(pypiClient)
			if err != nil {
				return fmt.Errorf("failed to create PyPI verifier: %w", err)
			}

			statuses, err := verifier.Verify(cmd.Context(), project, version)
			if err != nil {
				return fmt.Errorf("failed to verify PyPI package: %w", err)
			}

			for _, status := range statuses {
				fmt.Fprintf(os.Stdout, "⏳ Verifying file %s (SHA256: %s)\n", status.URL, status.SHA256)

				if !status.HasAttestation {
					fmt.Fprintln(os.Stdout, "❌ No attestations found")

					continue
				}

				if status.InferredIssuer == "" {
					fmt.Fprintln(os.Stdout, "❌ Could not infer a certificate issuer. Dangerously defaulting to skip identity checks.")
				} else {
					fmt.Fprintf(os.Stdout, "⚠️ Inferred certificate issuer %q\n", status.InferredIssuer)
				}

				if status.Error != nil {
					fmt.Fprintf(os.Stdout, "❌ Error verifying SigStore's provenance: %s\n", status.Error)
				} else {
					fmt.Fprintln(os.Stdout, "✅ Verified SigStore's provenance:")

					out, err := json.MarshalIndent(status.Attestation, "", "\t")
					if err != nil {
						return fmt.Errorf("marshalling SigStore's provenance: %w", err)
					}

					fmt.Fprintln(os.Stdout, string(out))
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "name of a PyPI project to verify")
	cmd.Flags().StringVar(&version, "version", "", "version of a PyPI project to verify")

	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("version")

	return cmd
}
