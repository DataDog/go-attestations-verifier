// The full specification for the API endpoints can be found at:
// https://github.com/npm/registry/blob/master/docs/REGISTRY-API.md
package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/DataDog/go-attestations-verifier/internal/httputil"
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

const Host = "registry.npmjs.org"

type Client struct {
	HTTP *http.Client
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

	err := httputil.GetJSON(ctx, url, &keys, httputil.WithClient(c.HTTP))
	if err != nil {
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

	err := httputil.GetJSON(ctx, url, &attestations, httputil.WithClient(c.HTTP))
	if err != nil {
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
	Repository      Repository        `json:"repository"`
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

// The `Repository` field in `PackageVersion` can have multiple types.
func (r *Repository) UnmarshalJSON(data []byte) error {
	var rawRepository interface{}

	err := json.Unmarshal(data, &rawRepository)
	if err != nil {
		return fmt.Errorf("parsing json encoded repository: %w", err)
	}

	// Observed for instance in old versions of https://registry.npmjs.org/postcss-normalize-charset.
	// The value had the form OWNER/REPO so we prepend "https://github.com" and append ".git" to match the other cases.
	// XXX: We assume the git provider is github.com but this may not always be the case.
	// Experimentally, this case seems to be rather and is probably related to an older version of NPM.
	// Recent packages that publish attestations should not fall through this case.
	if repository, ok := rawRepository.(string); ok {
		r.URL = fmt.Sprintf("https://github.com/%s.git", repository)
		r.Type = "git"
	}

	// Observed for instance in https://registry.npmjs.org/postcss-normalize-charset.
	// This seems to be the usual field type.
	if repository, ok := rawRepository.(map[string]interface{}); ok {
		r.URL = repository["url"].(string)   //nolint:forcetypeassert
		r.Type = repository["type"].(string) //nolint:forcetypeassert
	}

	// Observed for instance in https://registry.npmjs.org/tmp
	if repositories, ok := rawRepository.([]interface{}); ok {
		if len(repositories) > 0 {
			if repository, ok := repositories[0].(map[string]interface{}); ok {
				r.URL = repository["url"].(string)   //nolint:forcetypeassert
				r.Type = repository["type"].(string) //nolint:forcetypeassert
			}
		}
	}

	return nil
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

	err := httputil.GetJSON(ctx, url, &pkg, httputil.WithClient(c.HTTP))
	if err != nil {
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

	err := httputil.GetJSON(ctx, url, &pkg, httputil.WithClient(c.HTTP))
	if err != nil {
		return nil, fmt.Errorf("getting package: %w", err)
	}

	return &pkg, nil
}
