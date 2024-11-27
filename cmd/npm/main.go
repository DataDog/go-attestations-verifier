package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/DataDog/go-attestations-verifier/pkg/httputil"
	"github.com/DataDog/go-attestations-verifier/pkg/npm"
)

var name, version string

func main() {
	flag.StringVar(&name, "name", "", "name of a NPM package to verify")
	flag.StringVar(&version, "version", "", "version of a NPM package to verify")
	flag.Parse()

	ctx := context.Background()

	npmClient := &npm.Client{HTTP: httputil.DefaultClient()}

	pkg, err := npmClient.GetPackageVersion(ctx, name, version)
	if err != nil {
		log.Fatal(err)
	}

	verifier, err := npm.NewVerifier(ctx, npmClient)
	if err != nil {
		log.Fatal(err)
	}

	status, err := verifier.Verify(ctx, pkg)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(os.Stdout, "⏳ Verifying file %s (SHA512: %s)\n", status.URL, status.SHA512)

	if !status.HasAttestations {
		fmt.Fprintln(os.Stdout, "❌ No attestations found")

		return
	}

	if status.AttestationError != nil {
		fmt.Fprintf(os.Stdout, "❌ Error verifying NPM's attestation: %s\n", status.AttestationError)
	} else {
		fmt.Fprintln(os.Stdout, "✅ Verified NPM's signature with NPM public key")
	}

	if status.ProvenanceError != nil {
		fmt.Fprintf(os.Stdout, "❌ Error verifying SigStore's provenance: %s\n", status.ProvenanceError)
	} else {
		fmt.Fprintln(os.Stdout, "✅ Verified SigStore's provenance")
	}
}
