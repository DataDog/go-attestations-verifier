package main

import (
	"context"
	"flag"
	"log"

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

	if err := verifier.Verify(ctx, project, version); err != nil {
		log.Fatal(err)
	}
}
