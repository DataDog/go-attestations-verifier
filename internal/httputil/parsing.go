package httputil

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/verify"
)

func ParseSourceURL(rawURL string) (*url.URL, error) {
	url, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parsing source URL: %w", err)
	}

	url.Scheme = SchemeHTTPS
	url.Path = strings.TrimSuffix(url.Path, ".git")
	url.Path = strings.TrimSuffix(url.Path, "/")

	pathParts := strings.Split(strings.Trim(url.Path, "/"), "/")
	if len(pathParts) > 2 { //nolint:mnd
		pathParts = pathParts[:2]
	}

	url.Path = "/" + strings.Join(pathParts, "/")

	return url, nil
}

//nolint:gochecknoglobals
var IssuerByHost = map[string]string{
	"github.com": "https://token.actions.githubusercontent.com",
	"gitlab.com": "https://gitlab.com",
}

func GetCertID(source *url.URL) (verify.PolicyOption, error) {
	issuer, ok := IssuerByHost[source.Host]
	if !ok {
		return verify.WithoutIdentitiesUnsafe(), nil
	}

	certID, err := verify.NewShortCertificateIdentity(
		issuer, "", "", "^"+source.String(),
	)
	if err != nil {
		return nil, fmt.Errorf("creating certificate identity: %w", err)
	}

	return verify.WithCertificateIdentity(certID), nil
}
