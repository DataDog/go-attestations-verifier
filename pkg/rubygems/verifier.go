package rubygems

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/DataDog/go-attestations-verifier/internal/httputil"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	rekorbpb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/client"
	rekorClient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/tle"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

type Verifier struct {
	RubyGems *Client
	SigStore *verify.Verifier
	Rekor    *rekorClient.Rekor
}

func NewVerifier(rubygems *Client) (*Verifier, error) {
	trustedRoot, err := root.FetchTrustedRootWithOptions(
		tuf.DefaultOptions().WithCacheValidity(1),
	)
	if err != nil {
		return nil, fmt.Errorf("fetching TUF trusted root: %w", err)
	}

	rekor, err := client.GetRekorClient("https://rekor.sigstore.dev")
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
		Rekor:    rekor,
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

	bundle, err := v.getBundle(ctx, digest)
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

func (v *Verifier) getBundle(ctx context.Context, digest []byte) (*bundle.Bundle, error) {
	hash := "sha256:" + hex.EncodeToString(digest)

	indexSearchQuery := index.NewSearchIndexParamsWithContext(ctx)
	indexSearchQuery.SetQuery(&models.SearchIndex{Hash: hash})

	searchResponse, err := v.Rekor.Index.SearchIndex(indexSearchQuery)
	if err != nil {
		return nil, fmt.Errorf(": %w", err)
	}

	uuids := searchResponse.GetPayload()
	if len(uuids) == 0 {
		return nil, ErrNoRekorLogEntry
	}

	entryGetRequest := entries.NewGetLogEntryByUUIDParamsWithContext(ctx)
	entryGetRequest.SetEntryUUID(uuids[0])

	resp, err := v.Rekor.Entries.GetLogEntryByUUID(entryGetRequest)
	if err != nil {
		return nil, fmt.Errorf(": %w", err)
	}

	var anon models.LogEntryAnon
	for _, v := range resp.Payload {
		anon = v
		break
	}

	tle, err := tle.GenerateTransparencyLogEntry(anon)
	if err != nil {
		return nil, err
	}

	pb := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			TlogEntries: []*rekorbpb.TransparencyLogEntry{tle},
		},
	}

	return bundle.NewBundle(pb)
}
