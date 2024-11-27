// The full specification for the API endpoints can be found at:
// https://github.com/npm/registry/blob/master/docs/REGISTRY-API.md
package npm

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/DataDog/go-attestations-verifier/pkg/httputil"
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

const Host = "registry.npmjs.org"

type Client struct {
	HTTPClient *http.Client
}

type Key struct {
	Expires *string `json:"expires"`
	KeyID   string  `json:"keyid"`
	KeyType string  `json:"keytype"`
	Scheme  string  `json:"scheme"`
	Key     string  `json:"key"`
}

func (c *Client) GetPublicKeys(ctx context.Context) ([]Key, error) {
	url := url.URL{
		Scheme: httputil.SchemeHTTPS,
		Host:   Host,
		Path:   "/-/npm/v1/keys",
	}

	var keys struct {
		Keys []Key `json:"keys"`
	}

	if err := httputil.GetJSON(ctx, url, &keys, httputil.WithClient(c.HTTPClient)); err != nil {
		return nil, fmt.Errorf("getting public keys: %w", err)
	}

	return keys.Keys, nil
}

type AttestationBundle struct {
	PredicateType string         `json:"predicateType"`
	Bundle        *bundle.Bundle `json:"bundle"`
}

func (c *Client) GetAttestations(ctx context.Context, name, version string) ([]AttestationBundle, error) {
	url := url.URL{
		Scheme: httputil.SchemeHTTPS,
		Host:   Host,
		Path:   fmt.Sprintf("/-/npm/v1/attestations/%s@%s", name, version),
	}

	var attestations struct {
		Attestations []AttestationBundle `json:"attestations"`
	}

	if err := httputil.GetJSON(ctx, url, &attestations, httputil.WithClient(c.HTTPClient)); err != nil {
		return nil, fmt.Errorf("getting attestations: %w", err)
	}

	return attestations.Attestations, nil
}

type Package struct {
	ID             string                    `json:"_id"`
	Rev            string                    `json:"_rev"`
	Name           string                    `json:"name"`
	Description    string                    `json:"description"`
	DistTags       DistTags                  `json:"dist-tags"`
	Versions       map[string]PackageVersion `json:"versions"`
	Readme         string                    `json:"readme"`
	Maintainers    []Maintainer              `json:"maintainers"`
	Time           map[string]time.Time      `json:"time"`
	ReadmeFilename string                    `json:"readmeFilename"`
	Keywords       []string                  `json:"keywords"`
	Users          map[string]bool           `json:"users"`
	Homepage       string                    `json:"homepage"`
}

// Some additional fields exist but they can have multiple types.
// This causes errors at json.Unmarshal time if the field does not have the righ type.
// There are simply excluded them from the struct for now as they are not used elsewhere in the code.
type PackageVersion struct {
	Name            string            `json:"name"`
	Description     string            `json:"description"`
	Version         string            `json:"version"`
	Repository      interface{}       `json:"repository"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	GitHead         string            `json:"gitHead"`
	ID              string            `json:"_id"`
	NodeVersion     string            `json:"_nodeVersion"`
	NpmVersion      string            `json:"_npmVersion"`
	Dist            Dist              `json:"dist"`
	NpmUser         User              `json:"_npmUser"`
	HasShrinkwrap   bool              `json:"_hasShrinkwrap"`
}

type Repository struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type Signature struct {
	Keyid string `json:"keyid"`
	Sig   string `json:"sig"`
}

type Attestation struct {
	URL        string     `json:"url"`
	Provenance Provenance `json:"attestation"`
}

type Provenance struct {
	PredicateType string `json:"predicateType"`
}

type Dist struct {
	Integrity    string      `json:"integrity"`
	Shasum       string      `json:"shasum"`
	Tarball      string      `json:"tarball"`
	FileCount    int         `json:"fileCount"`
	UnpackedSize int         `json:"unpackedSize"`
	Signatures   []Signature `json:"signatures"`
	Attestations Attestation `json:"attestations"`
	NpmSignature string      `json:"npm-signature"`
}

type DistTags struct {
	Latest string `json:"latest"`
}

type User struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type Maintainer struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

func (c *Client) GetPackageVersion(ctx context.Context, name, version string) (*PackageVersion, error) {
	url := url.URL{
		Scheme: httputil.SchemeHTTPS,
		Host:   Host,
		Path:   fmt.Sprintf("/%s/%s", name, version),
	}

	var pkg PackageVersion
	if err := httputil.GetJSON(ctx, url, &pkg, httputil.WithClient(c.HTTPClient)); err != nil {
		return nil, fmt.Errorf("getting package version: %w", err)
	}

	return &pkg, nil
}

func (c *Client) GetPackage(ctx context.Context, name string) (*Package, error) {
	url := url.URL{
		Scheme: httputil.SchemeHTTPS,
		Host:   Host,
		Path:   "/" + name,
	}

	var pkg Package
	if err := httputil.GetJSON(ctx, url, &pkg, httputil.WithClient(c.HTTPClient)); err != nil {
		return nil, fmt.Errorf("getting package: %w", err)
	}

	return &pkg, nil
}
