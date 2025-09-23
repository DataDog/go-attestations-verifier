// The full specification for this API endpoint can be found at:
// https://guides.rubygems.org/rubygems-org-api-v2/
package rubygems

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/DataDog/go-attestations-verifier/internal/httputil"
)

const Host = "rubygems.org"

type Client struct {
	HTTP *http.Client
}

type GemVersion struct {
	Name             string             `json:"name"`
	Downloads        int                `json:"downloads"`
	Version          string             `json:"version"`
	VersionCreatedAt string             `json:"version_created_at"`
	VersionDownloads int                `json:"version_downloads"`
	Platform         string             `json:"platform"`
	Authors          string             `json:"authors"`
	Info             string             `json:"info"`
	Licenses         []string           `json:"licenses"`
	Metadata         map[string]*string `json:"metadata"`
	Yanked           bool               `json:"yanked"`
	SHA              string             `json:"sha"`
	SpecSHA          string             `json:"spec_sha"`
	ProjectURI       string             `json:"project_uri"`
	GemURI           string             `json:"gem_uri"`
	HomepageURI      string             `json:"homepage_uri"`
	WikiURI          *string            `json:"wiki_uri"`
	DocumentationURI *string            `json:"documentation_uri"`
	MailingListURI   *string            `json:"mailing_list_uri"`
	SourceCodeURI    string             `json:"source_code_uri"`
	BugTrackerURI    *string            `json:"bug_tracker_uri"`
	ChangelogURI     string             `json:"changelog_uri"`
	FundingURI       *string            `json:"funding_uri"`
	Dependencies     Dependencies       `json:"dependencies"`
	BuiltAt          string             `json:"built_at"`
	CreatedAt        string             `json:"created_at"`
	Description      string             `json:"description"`
	DownloadsCount   int                `json:"downloads_count"`
	Number           string             `json:"number"`
	Summary          string             `json:"summary"`
	RubygemsVersion  string             `json:"rubygems_version"`
	RubyVersion      string             `json:"ruby_version"`
	Prerelease       bool               `json:"prerelease"`
	Requirements     []string           `json:"requirements"`
}

type Dependencies struct {
	Development []Dependency `json:"development"`
	Runtime     []Dependency `json:"runtime"`
}

type Dependency struct {
	Name         string `json:"name"`
	Requirements string `json:"requirements"`
}

func (c *Client) GetGemVersion(ctx context.Context, name, version string) (*GemVersion, error) {
	url := url.URL{
		Scheme: httputil.SchemeHTTPS,
		Host:   Host,
		Path:   fmt.Sprintf("/api/v2/rubygems/%s/versions/%s.json", name, version),
	}

	var gem GemVersion

	err := httputil.GetJSON(
		ctx, url, &gem,
		httputil.WithClient(c.HTTP),
	)
	if err != nil {
		return nil, fmt.Errorf("getting gem version: %w", err)
	}

	return &gem, nil
}
