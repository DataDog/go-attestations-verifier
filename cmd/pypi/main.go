package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/DataDog/go-attestations-verifier/pkg/httputil"
	"github.com/DataDog/go-attestations-verifier/pkg/pypi"
)

var name, version string

func main() {
	flag.StringVar(&name, "name", "", "name of a PyPI project to verify")
	flag.StringVar(&version, "version", "", "version of a PyPI project to verify")
	flag.Parse()

	ctx := context.Background()

	pypiClient := &pypi.Client{HTTP: httputil.DefaultClient()}

	project, err := pypiClient.GetProject(ctx, name)
	if err != nil {
		log.Fatal(err)
	}

	verifier, err := pypi.NewVerifier(pypiClient)
	if err != nil {
		log.Fatal(err)
	}

	statuses, err := verifier.Verify(ctx, project, version)
	if err != nil {
		log.Fatal(err)
	}

	for _, status := range statuses {
		fmt.Fprintf(os.Stdout, "⏳ Verifying file %s (SHA256: %s)\n", status.URL, status.SHA256)

		if !status.HasAttestation {
			fmt.Fprintln(os.Stdout, "❌ No attestations found")

			continue
		}

		if status.Error != nil {
			fmt.Fprintf(os.Stdout, "❌ Error verifying SigStore's provenance: %s\n", status.Error)
		} else {
			fmt.Fprintln(os.Stdout, "✅ Verified SigStore's provenance")
		}
	}
}
