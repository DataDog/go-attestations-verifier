package npm_test

import (
	"context"
	"log"

	"github.com/DataDog/go-attestations-verifier/internal/httputil"
	"github.com/DataDog/go-attestations-verifier/pkg/npm"
)

//nolint:testableexamples
func ExampleVerifier_Verify() {
	ctx := context.Background()

	npmClient := &npm.Client{HTTP: httputil.DefaultClient()}

	pkg, err := npmClient.GetPackageVersion(ctx, "sigstore", "3.0.0")
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

	log.Print(status)
}
