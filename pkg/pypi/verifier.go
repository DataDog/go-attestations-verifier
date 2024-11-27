package pypi

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"

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
	SigStore *verify.SignedEntityVerifier
}

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

func (v *Verifier) Verify(ctx context.Context, project *ProjectVersion) error {
	for _, release := range project.Releases {
		provenance, err := v.PyPI.GetProvenance(ctx, project.Info.Name, project.Info.Version, release.Filename)
		if err != nil {
			return err
		}

		digest, err := hex.DecodeString(release.Digests.Sha256)
		if err != nil {
			return fmt.Errorf("decoding hex encoded release's sha256 digest: %w", err)
		}

		for _, bundles := range provenance.AttestationBundles {
			for _, attestation := range bundles.Attestations {
				bundle, err := transcribeBundle(attestation)
				if err != nil {
					return err
				}

				if err := v.verifyBundle(bundle, digest); err != nil {
					return err
				}
			}
		}
	}

	return nil
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

func (v *Verifier) verifyBundle(bundle *bundle.Bundle, digest []byte) error {
	if _, err := v.SigStore.Verify(
		bundle,
		verify.NewPolicy(
			verify.WithArtifactDigest("sha256", digest),
			verify.WithoutIdentitiesUnsafe(), // TODO: check specific cert identities
		),
	); err != nil {
		return fmt.Errorf("verifying a bundle: %w", err)
	}

	return nil
}
