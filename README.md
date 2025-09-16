# go-attestations-verifier

A Golang library to verify [NPM](https://www.npmjs.com/) and [PyPI](https://pypi.org/) [sigstore](https://www.sigstore.dev/) attestations.

## Getting started

For convenience, a Go command is provided in this repository to quickly check for a package's status. One can use it like this:
```shell
go run ./cmd npm --name sigstore --version 3.0.0 # Signed NPM package
go run ./cmd npm --name @testing-library/jest-dom --version 6.6.3 # Unsigned NPM package
go run ./cmd pypi --name sampleproject --version 4.0.0 # Signed PyPI package
go run ./cmd pypi --name sigstore --version 3.0.0 # Unsigned PyPI package
```

Two packages are provided for programmatic usage: [./pkg/npm](./pkg/npm) and [./pkg/pypi](./pkg/pypi).
Each one defines a `Client` exposing methods to interact with both registries over HTTP.

> Both `Client` structs are simply wrappers around `*http.Client` meaning they are safe to use concurrently.

Each package also defines a `Verifier` exposing a `Verify` method to check attestations for a given package.

Check out [./pkg/npm/verifier_test.go](./pkg/npm/verifier_test.go) and [./pkg/pypi/verifier_test.go](./pkg/pypi/verifier_test.go) to see some basic examples of both `Verifier`s usage.

### NPM specificities

NPM supports sigstore attestations as documented in https://docs.npmjs.com/generating-provenance-statements.

They expose an endpoint serving attestations for a given package's version.

The attestation pushing process supports GitHub Actions and Gitlab CI/CD (see https://docs.npmjs.com/generating-provenance-statements#provenance-limitations).

A NPM version is mapped to a single `.tar` file. If available, there are two attestations for such a file:
- one public key signature one can verify with NPM's public keys (available at https://registry.npmjs.org/-/npm/v1/keys).
- one sigstore provenance attestation one can verify using the sigstore certificate chain.

`npm.Verifier` verifies both attestations. It infers the certificate issuer and Subject Alternative Name (SAN) from the package metadata source URL.

### PyPI specificities

In https://blog.pypi.org/posts/2024-11-14-pypi-now-supports-digital-attestations/, PyPI announced support for sigstore attestations.

They released a new API endpoint documented at https://docs.pypi.org/api/integrity/ one can use to retrieve attestations for a specific file released for a project version and verify them using the sigstore certificate chain.

The recommended attestation publishing process involves using the GitHub action https://github.com/pypa/gh-action-pypi-publish.

Most project versions releases contain two files (a `.whl` and a `.tar`). `pypi.Verifier` verifies all files for a given version. It infers the certificate issuer and Subject Alternative Name (SAN) from the project metadata source URL.

## Development

### Lint the code

```shell
brew install golangci-lint
golangci-lint run
```

### Regenerate the LICENSE-3rdparty.csv file

```shell
go install github.com/google/go-licenses
$GOPATH/bin/go-licenses report github.com/DataDog/go-attestations-verifier/cmd | sort > ./LICENSE-3rdparty.csv
```
