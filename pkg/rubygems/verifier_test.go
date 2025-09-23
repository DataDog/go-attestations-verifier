package rubygems_test

import (
	"context"
	"log"

	"github.com/DataDog/go-attestations-verifier/internal/httputil"
	"github.com/DataDog/go-attestations-verifier/pkg/rubygems"
)

//nolint:testableexamples
func ExampleVerifier_Verify() {
	ctx := context.Background()

	rubygemsClient := &rubygems.Client{HTTP: httputil.DefaultClient()}

	gem, err := rubygemsClient.GetGemVersion(ctx, "sigstore", "0.2.1")
	if err != nil {
		log.Fatal(err)
	}

	verifier, err := rubygems.NewVerifier(rubygemsClient)
	if err != nil {
		log.Fatal(err)
	}

	status, err := verifier.Verify(ctx, gem)
	if err != nil {
		log.Fatal(err)
	}

	log.Print(status)
}
