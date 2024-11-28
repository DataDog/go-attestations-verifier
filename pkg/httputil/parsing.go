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

	return url, nil
}

func GetCertID(source *url.URL) (verify.PolicyOption, error) {
	if source.Host == "github.com" {
		certID, err := verify.NewShortCertificateIdentity(
			"https://token.actions.githubusercontent.com",
			"", "", "^"+source.String(),
		)
		if err != nil {
			return nil, fmt.Errorf("creating certificate identity: %w", err)
		}

		return verify.WithCertificateIdentity(certID), nil
	}

	if source.Host == "gitlab.com" {
		certID, err := verify.NewShortCertificateIdentity(
			"https://gitlab.com",
			"", "", "^"+source.String(),
		)
		if err != nil {
			return nil, fmt.Errorf("creating certificate identity: %w", err)
		}

		return verify.WithCertificateIdentity(certID), nil
	}

	return verify.WithoutIdentitiesUnsafe(), nil
}
