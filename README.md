# go-attestations-verifier

A Golang library to verify NPM and PyPI sigstore attestations.

## Getting started

For convenience, two Go commands are provided in this repository to quickly check for a package's status. One can use them like this:
```shell
go run ./cmd/npm/ -name sigstore -version 3.0.0 # Signed NPM package
go run ./cmd/npm/ -name @testing-library/jest-dom -version 6.6.3 # Unsigned NPM package
go run ./cmd/pypi/ -name sampleproject -version 4.0.0 # Signed PyPI package
go run ./cmd/pypi/ -name sigstore -version 3.0.0 # Unsigned PyPI package
```
