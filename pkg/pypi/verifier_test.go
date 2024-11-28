package pypi_test

import (
	"context"
	"log"

	"github.com/DataDog/go-attestations-verifier/internal/httputil"
	"github.com/DataDog/go-attestations-verifier/pkg/pypi"
)

//nolint:testableexamples
func ExampleVerifier_Verify() {
	ctx := context.Background()

	pypiClient := &pypi.Client{HTTP: httputil.DefaultClient()}

	project, err := pypiClient.GetProject(ctx, "sampleproject")
	if err != nil {
		log.Fatal(err)
	}

	verifier, err := pypi.NewVerifier(pypiClient)
	if err != nil {
		log.Fatal(err)
	}

	status, err := verifier.Verify(ctx, project, "4.0.0")
	if err != nil {
		log.Fatal(err)
	}

	log.Print(status)
}
