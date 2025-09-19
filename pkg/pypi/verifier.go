package pypi

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"github.com/DataDog/go-attestations-verifier/internal/httputil"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protosigstore "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

type Verifier struct {
	PyPI     *Client
	SigStore *verify.Verifier
}

func NewVerifier(pypi *Client) (*Verifier, error) {
	trustedRoot, err := root.FetchTrustedRootWithOptions(
		tuf.DefaultOptions().WithCacheValidity(1),
	)
	if err != nil {
		return nil, fmt.Errorf("fetching TUF trusted root: %w", err)
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
		PyPI:     pypi,
		SigStore: sigstore,
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

//nolint:cyclop,funlen
func (v *Verifier) Verify(ctx context.Context, project *Project, version string) ([]*VerificationStatus, error) {
	releases, ok := project.Releases[version]
	if !ok {
		return nil, ErrMissingReleases
	}

	source, err := httputil.ParseSourceURL(project.Info.ProjectUrls.Source)
	if err != nil {
		return nil, fmt.Errorf("parsing source url: %w", err)
	}

	certID, err := httputil.GetCertID(source)
	if err != nil {
		return nil, fmt.Errorf("inferring certificate id: %w", err)
	}

	statuses := make([]*VerificationStatus, len(releases))

	for index, release := range releases {
		statuses[index] = &VerificationStatus{
			URL:            release.URL,
			SHA256:         release.Digests.Sha256,
			InferredIssuer: httputil.IssuerByHost[source.Host],
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

				// XXX: the current format allows multiple attestations per release, and multiple sigstore bundles per attestations.
				// However it seems they only contain a single sigstore provenance so far which is what this code assumes for now.
				statuses[index].Attestation, statuses[index].Error = v.SigStore.Verify(
					bundle,
					verify.NewPolicy(
						verify.WithArtifactDigest("sha256", digest),
						certID,
					),
				)
			}
		}
	}

	return statuses, nil
}

// transcribeBundle returns a sigstore bundle (as defined
// in https://github.com/sigstore/cosign/blob/main/specs/BUNDLE_SPEC.md) based on a PyPI attestation.
// This way we can use the sigstore-go library to verify the bundle later.
// PyPI uses a slightly different format than sigstore to stores attestations in. Basically both provides:
//   - a signature (typically a DSSE envelope)
//   - verification materials that can be used by the verifier to verify the signature
//     (typically a public key identifier or a certificate chain).
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
	return &bundle.Bundle{
		Bundle: &protobundle.Bundle{
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
		},
	}, nil
}
