package pypi

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"github.com/DataDog/go-attestations-verifier/pkg/httputil"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protosigstore "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

func NewVerifier(pypi *Client) (*Verifier, error) {
	trustedRoot, err := root.FetchTrustedRootWithOptions(
		tuf.DefaultOptions().WithCacheValidity(1),
	)
	if err != nil {
		return nil, fmt.Errorf("fetching TUF trusted root: %w", err)
	}

	sigstore, err := verify.NewSignedEntityVerifier(
		trustedRoot,
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("creating sigstore verifier: %w", err)
	}

	return &Verifier{
		PyPI:     pypi,
		SigStore: sigstore,
	}, nil
}

type Verifier struct {
	PyPI     *Client
	SigStore *verify.SignedEntityVerifier
}

type VerificationStatus struct {
	URL            string
	SHA256         string
	HasAttestation bool
	Attestation    *verify.VerificationResult
	Error          error
}

func (v *Verifier) Verify(ctx context.Context, project *Project, version string) ([]*VerificationStatus, error) {
	releases, ok := project.Releases[version]
	if !ok {
		return nil, fmt.Errorf("No releases for version %q of project %q", version, project.Info.Name)
	}

	statuses := make([]*VerificationStatus, len(releases))

	for index, release := range releases {
		statuses[index] = &VerificationStatus{
			URL:    release.URL,
			SHA256: release.Digests.Sha256,
		}

		provenance, err := v.PyPI.GetProvenance(ctx, project.Info.Name, version, release.Filename)
		if err != nil {
			var httperr *httputil.HTTPStatusError
			if errors.As(err, &httperr) && httperr.StatusCode == http.StatusNotFound {
				continue
			}

			statuses[index].Error = err

			continue
		}

		statuses[index].HasAttestation = true

		digest, err := hex.DecodeString(release.Digests.Sha256)
		if err != nil {
			statuses[index].Error = fmt.Errorf("decoding hex encoded release's sha256 digest: %w", err)

			continue
		}

		for _, bundles := range provenance.AttestationBundles {
			for _, attestation := range bundles.Attestations {
				bundle, err := transcribeBundle(attestation)
				if err != nil {
					statuses[index].Error = err

					continue
				}

				statuses[index].Attestation, statuses[index].Error = v.verifyBundle(bundle, digest)
			}
		}
	}

	return statuses, nil
}

func transcribeBundle(attestation Attestation) (*bundle.Bundle, error) {
	cert, err := base64.StdEncoding.DecodeString(attestation.VerificationMaterials.Certificate)
	if err != nil {
		return nil, fmt.Errorf("decoding base64 encoded certificate: %w", err)
	}

	signature, err := base64.StdEncoding.DecodeString(attestation.Envelope.Signature)
	if err != nil {
		return nil, fmt.Errorf("decoding base64 encoded dsse signature: %w", err)
	}

	payload, err := base64.StdEncoding.DecodeString(attestation.Envelope.Statement)
	if err != nil {
		return nil, fmt.Errorf("decoding base64 encoded dsse payload: %w", err)
	}

	// This is inspired by https://github.com/trailofbits/pypi-attestations/blob/main/src/pypi_attestations/_impl.py#L246
	return &bundle.Bundle{Bundle: &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protosigstore.X509Certificate{RawBytes: cert},
			},
			TlogEntries: attestation.VerificationMaterials.TransparencyEntries,
		},
		Content: &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: &dsse.Envelope{
				Payload:     payload,
				PayloadType: "application/vnd.in-toto+json",
				Signatures:  []*dsse.Signature{{Sig: signature}},
			},
		},
	}}, nil
}

func (v *Verifier) verifyBundle(bundle *bundle.Bundle, digest []byte) (*verify.VerificationResult, error) {
	result, err := v.SigStore.Verify(
		bundle,
		verify.NewPolicy(
			verify.WithArtifactDigest("sha256", digest),
			verify.WithoutIdentitiesUnsafe(), // TODO: check specific cert identities
		),
	)
	if err != nil {
		return nil, fmt.Errorf("verifying a bundle: %w", err)
	}

	return result, nil
}
