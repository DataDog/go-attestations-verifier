package main

import (
	"context"
	"flag"
	"log"

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

	project, err := npmClient.GetPackageVersion(ctx, name, version)
	if err != nil {
		log.Fatal(err)
	}

	verifier, err := npm.NewVerifier(ctx, npmClient)
	if err != nil {
		log.Fatal(err)
	}

	if err := verifier.Verify(ctx, project); err != nil {
		log.Fatal(err)
	}
}
