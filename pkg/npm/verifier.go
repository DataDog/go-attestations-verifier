package npm

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
)

func NewVerifier(ctx context.Context, npm *Client, trustedRoot *root.TrustedRoot) (*Verifier, error) {
	sigstore, err := verify.NewSignedEntityVerifier(
		trustedRoot,
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("creating sigstore verifier: %w", err)
	}

	npmPublicKey, err := NewNPMPublicKeyVerifier(ctx, npm, trustedRoot)
	if err != nil {
		return nil, err
	}

	return &Verifier{
		NPM:          npm,
		SigStore:     sigstore,
		NPMPublicKey: npmPublicKey,
	}, nil
}

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

func NewNPMPublicKeyVerifier(
	ctx context.Context,
	npm *Client,
	trustedRoot *root.TrustedRoot,
) (*verify.SignedEntityVerifier, error) {
	publicKeys, err := npm.GetPublicKeys(ctx)
	if err != nil {
		return nil, err
	}

	if len(publicKeys) == 0 {
		return nil, fmt.Errorf("No public keys returned by NPM")
	}

	// XXX: There's only one public key provided by NPM at the moment.
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeys[0].Key)
	if err != nil {
		return nil, fmt.Errorf("decoding base64 encoded public key: %w", err)
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	verifier, err := signature.LoadVerifier(publicKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("loading verifier: %w", err)
	}

	sev, err := verify.NewSignedEntityVerifier(&verifyTrustedMaterial{
		TrustedMaterial: trustedRoot,
		keyTrustedMaterial: root.NewTrustedPublicKeyMaterial(func(_ string) (root.TimeConstrainedVerifier, error) {
			return root.NewExpiringKey(verifier, time.Time{}, time.Time{}), nil
		}),
	}, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	if err != nil {
		return nil, fmt.Errorf("creating new verifier: %w", err)
	}

	return sev, nil
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
