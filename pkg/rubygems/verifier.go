package rubygems

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/DataDog/go-attestations-verifier/internal/httputil"
	"github.com/DataDog/go-attestations-verifier/pkg/rekor"
	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

type Verifier struct {
	RubyGems *Client
	SigStore *verify.Verifier
	Rekor    *rekor.Client
}

func NewVerifier(rubygems *Client) (*Verifier, error) {
	trustedRoot, err := root.FetchTrustedRootWithOptions(
		tuf.DefaultOptions().WithCacheValidity(1),
	)
	if err != nil {
		return nil, fmt.Errorf("fetching TUF trusted root: %w", err)
	}

	rekorClient, err := client.GetRekorClient("https://rekor.sigstore.dev")
	if err != nil {
		return nil, fmt.Errorf("creating rekor client: %w", err)
	}

	sigstore, err := verify.NewVerifier(
		trustedRoot,
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("creating sigstore verifier: %w", err)
	}

	return &Verifier{
		RubyGems: rubygems,
		SigStore: sigstore,
		Rekor:    &rekor.Client{Rekor: rekorClient},
	}, nil
}

type VerificationStatus struct {
	URL            string
	SHA256         string
	InferredIssuer string
	HasAttestation bool
	Attestation    *verify.VerificationResult
	Error          error
}

func (v *Verifier) Verify(ctx context.Context, gem *GemVersion) (*VerificationStatus, error) {
	source, err := httputil.ParseSourceURL(gem.SourceCodeURI)
	if err != nil {
		return nil, fmt.Errorf("parsing source url: %w", err)
	}

	certID, err := httputil.GetCertID(source)
	if err != nil {
		return nil, fmt.Errorf("inferring certificate id: %w", err)
	}

	digest, err := hex.DecodeString(gem.SHA)
	if err != nil {
		return nil, fmt.Errorf("decoding hex encoded package's version sha256: %w", err)
	}

	status := &VerificationStatus{
		URL:            gem.GemURI,
		SHA256:         gem.SHA,
		InferredIssuer: httputil.IssuerByHost[source.Host],
	}

	bundle, err := v.Rekor.GetBundle(ctx, digest)
	if err != nil {
		return nil, fmt.Errorf("getting bundle: %w", err)
	}

	status.HasAttestation = true

	status.Attestation, status.Error = v.SigStore.Verify(
		bundle,
		verify.NewPolicy(
			verify.WithArtifactDigest("sha256", digest),
			certID,
		),
	)

	return status, nil
}
