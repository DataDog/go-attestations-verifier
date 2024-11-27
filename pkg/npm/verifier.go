package npm

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

type Verifier struct {
	NPM          *Client
	SigStore     *verify.SignedEntityVerifier
	NPMPublicKey *verify.SignedEntityVerifier
}

func (v *Verifier) Verify(ctx context.Context, pkg *PackageVersion) error {
	attestations, err := v.NPM.GetAttestations(ctx, pkg.Name, pkg.Version)
	if err != nil {
		return err
	}

	encodedDigest, ok := strings.CutPrefix(pkg.Dist.Integrity, "sha512-")
	if !ok {
		return fmt.Errorf("sha512 digest not found for package's version")
	}

	digest, err := base64.StdEncoding.DecodeString(encodedDigest)
	if err != nil {
		return fmt.Errorf("decoding base64 encoded package's version sha512: %w", err)
	}

	for _, attestation := range attestations {
		if attestation.PredicateType == "https://github.com/npm/attestation/tree/main/specs/publish/v0.1" {
			if err := v.verifyAttestation(attestation.Bundle, digest); err != nil {
				return err
			}
		}

		if attestation.PredicateType == "https://slsa.dev/provenance/v1" {
			if err := v.verifyProvenance(attestation.Bundle, digest); err != nil {
				return err
			}
		}
	}

	return nil
}

// Verification logic taken from:
// https://github.com/sigstore/sigstore-go/blob/main/docs/verification.md
func (v *Verifier) verifyAttestation(bundle *bundle.Bundle, digest []byte) error {
	if _, err := v.NPMPublicKey.Verify(
		bundle,
		verify.NewPolicy(
			verify.WithArtifactDigest("sha512", digest),
			verify.WithKey(),
		),
	); err != nil {
		return fmt.Errorf("verifying a bundle: %w", err)
	}

	return nil
}

func (v *Verifier) verifyProvenance(bundle *bundle.Bundle, digest []byte) error {
	// TODO: check specific cert identities
	if _, err := v.SigStore.Verify(
		bundle,
		verify.NewPolicy(
			verify.WithArtifactDigest("sha512", digest),
			verify.WithoutIdentitiesUnsafe(),
		),
	); err != nil {
		return fmt.Errorf("verifying a bundle: %w", err)
	}

	return nil
}

type verifyTrustedMaterial struct {
	root.TrustedMaterial
	keyTrustedMaterial root.TrustedMaterial
}

func (v *verifyTrustedMaterial) PublicKeyVerifier(hint string) (root.TimeConstrainedVerifier, error) {
	tcv, err := v.keyTrustedMaterial.PublicKeyVerifier(hint)
	if err != nil {
		return nil, fmt.Errorf("creating a time constrained verifier: %w", err)
	}

	return tcv, nil
}
