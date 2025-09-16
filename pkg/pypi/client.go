// The full specification for this API endpoint can be found at:
// https://warehouse.pypa.io/api-reference/json.html#project
package pypi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/DataDog/go-attestations-verifier/internal/httputil"
	rekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const Host = "pypi.org"

type Client struct {
	HTTP *http.Client
}

// PyPI seems to use a slightly custom AttestationBundle format
// documented at https://docs.pypi.org/api/integrity/
type Provenance struct {
	Version            int                 `json:"version"`
	AttestationBundles []AttestationBundle `json:"attestation_bundles"`
}

type AttestationBundle struct {
	Attestations []Attestation `json:"attestations"`
	Publisher    Publisher     `json:"publisher"`
}

type Publisher struct {
	Environment string `json:"environment"`
	Kind        string `json:"kind"`
	Repository  string `json:"repository"`
	Workflow    string `json:"workflow"`
}

type Attestation struct {
	Version               int                   `json:"version"`
	Envelope              Envelope              `json:"envelope"`
	VerificationMaterials VerificationMaterials `json:"verification_material"`
}

type Envelope struct {
	Signature string `json:"signature"`
	Statement string `json:"statement"`
}

type VerificationMaterials struct {
	Certificate         string                        `json:"certificate"`
	TransparencyEntries []*rekor.TransparencyLogEntry `json:"transparency_entries"`
}

// This is required as PyPI returns JSON serialized protobuf transparency entries.
func (v *VerificationMaterials) UnmarshalJSON(bytes []byte) error {
	var raw struct {
		Certificate         string `json:"certificate"`
		TransparencyEntries []any  `json:"transparency_entries"`
	}

	err := json.Unmarshal(bytes, &raw)
	if err != nil {
		return fmt.Errorf("parsing json encoded verification materials: %w", err)
	}

	v.Certificate = raw.Certificate
	v.TransparencyEntries = []*rekor.TransparencyLogEntry{}

	for _, entry := range raw.TransparencyEntries {
		serializedEntries, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("encoding a rekor transparency entry to json: %w", err)
		}

		var parsedEntry rekor.TransparencyLogEntry

		err = protojson.Unmarshal(serializedEntries, &parsedEntry)
		if err != nil {
			return fmt.Errorf("parsing a protojson encoded rekor transparency log entry: %w", err)
		}

		v.TransparencyEntries = append(v.TransparencyEntries, &parsedEntry)
	}

	return nil
}

func (c *Client) GetProvenance(ctx context.Context, name, version, filename string) (*Provenance, error) {
	url := url.URL{
		Scheme: httputil.SchemeHTTPS,
		Host:   Host,
		Path:   fmt.Sprintf("/integrity/%s/%s/%s/provenance", name, version, filename),
	}

	var provenance Provenance

	err := httputil.GetJSON(
		ctx, url, &provenance,
		httputil.WithClient(c.HTTP),
		httputil.WithHeader("Accept", "application/vnd.pypi.integrity.v1+json"),
	)
	if err != nil {
		return nil, fmt.Errorf("getting provenance: %w", err)
	}

	return &provenance, nil
}

type Project struct {
	Info            Info                 `json:"info"`
	LastSerial      int                  `json:"last_serial"`
	Releases        map[string][]Release `json:"releases"`
	Urls            []Release            `json:"urls"`
	Vulnerabilities []Vulnerability      `json:"vulnerabilities"`
}

type Info struct {
	Author                 string      `json:"author"`
	AuthorEmail            string      `json:"author_email"`
	BugtrackURL            string      `json:"bugtrack_url"`
	Classifiers            []string    `json:"classifiers"`
	Description            string      `json:"description"`
	DescriptionContentType string      `json:"description_content_type"`
	DocsURL                string      `json:"docs_url"`
	DownloadURL            string      `json:"download_url"`
	Downloads              Downloads   `json:"downloads"`
	HomePage               string      `json:"home_page"`
	Keywords               string      `json:"keywords"`
	License                string      `json:"license"`
	Maintainer             string      `json:"maintainer"`
	MaintainerEmail        string      `json:"maintainer_email"`
	Name                   string      `json:"name"`
	PackageURL             string      `json:"package_url"`
	Platform               string      `json:"platform"`
	ProjectURL             string      `json:"project_url"`
	ProjectUrls            ProjectUrls `json:"project_urls"`
	ReleaseURL             string      `json:"release_url"`
	RequiresDist           []string    `json:"requires_dist"`
	RequiresPython         string      `json:"requires_python"`
	Summary                string      `json:"summary"`
	Version                string      `json:"version"`
	Yanked                 bool        `json:"yanked"`
	YankedReason           string      `json:"yanked_reason"`
}

type Downloads struct {
	LastDay   int `json:"last_day"`
	LastMonth int `json:"last_month"`
	LastWeek  int `json:"last_week"`
}

type ProjectUrls struct {
	BugReports string `json:"Bug Reports"`
	Funding    string `json:"Funding"`
	Homepage   string `json:"Homepage"`
	SayThanks  string `json:"Say Thanks!"`
	Source     string `json:"Source"`
}

type Release struct {
	CommentText       string    `json:"comment_text"`
	Digests           Digests   `json:"digests"`
	Downloads         int       `json:"downloads"`
	Filename          string    `json:"filename"`
	HasSig            bool      `json:"has_sig"`
	Md5Digest         string    `json:"md5_digest"`
	Packagetype       string    `json:"packagetype"`
	PythonVersion     string    `json:"python_version"`
	RequiresPython    string    `json:"requires_python"`
	Size              int       `json:"size"`
	UploadTime        string    `json:"upload_time"`
	UploadTimeIso8601 time.Time `json:"upload_time_iso_8601"`
	URL               string    `json:"url"`
	Yanked            bool      `json:"yanked"`
	YankedReason      string    `json:"yanked_reason"`
}

type Digests struct {
	Blake2B256 string `json:"blake2b_256"`
	Md5        string `json:"md5"`
	Sha256     string `json:"sha256"`
}

type Vulnerability struct {
	Aliases   []string  `json:"aliases"`
	Details   string    `json:"details"`
	Summary   string    `json:"summary"`
	FixedIn   []string  `json:"fixed_in"`
	ID        string    `json:"id"`
	Link      string    `json:"link"`
	Source    string    `json:"source"`
	Withdrawn time.Time `json:"withdrawn"`
}

func (c *Client) GetProject(ctx context.Context, name string) (*Project, error) {
	url := url.URL{
		Scheme: httputil.SchemeHTTPS,
		Host:   Host,
		Path:   fmt.Sprintf("/pypi/%s/json", name),
	}

	var project Project

	err := httputil.GetJSON(ctx, url, &project, httputil.WithClient(c.HTTP))
	if err != nil {
		return nil, fmt.Errorf("getting project: %w", err)
	}

	return &project, nil
}
