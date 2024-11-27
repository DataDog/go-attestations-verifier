package npm

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/DataDog/go-attestations-verifier/pkg/httputil"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
)

func NewVerifier(ctx context.Context, npm *Client) (*Verifier, error) {
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

type VerificationStatus struct {
	URL              string
	SHA512           string
	HasAttestations  bool
	Attestation      *verify.VerificationResult
	AttestationError error
	Provenance       *verify.VerificationResult
	ProvenanceError  error
}

func (v *Verifier) Verify(ctx context.Context, pkg *PackageVersion) (*VerificationStatus, error) {
	status := &VerificationStatus{
		URL: pkg.Dist.Tarball,
	}

	encodedDigest, ok := strings.CutPrefix(pkg.Dist.Integrity, "sha512-")
	if !ok {
		return nil, fmt.Errorf("sha512 digest not found for package's version")
	}

	status.SHA512 = encodedDigest

	digest, err := base64.StdEncoding.DecodeString(encodedDigest)
	if err != nil {
		return nil, fmt.Errorf("decoding base64 encoded package's version sha512: %w", err)
	}

	attestations, err := v.NPM.GetAttestations(ctx, pkg.Name, pkg.Version)
	if err != nil {
		var httperr *httputil.HTTPStatusError
		if errors.As(err, &httperr) && httperr.StatusCode == http.StatusNotFound {
			return status, nil
		}

		return nil, err
	}

	status.HasAttestations = true

	for _, attestation := range attestations {
		if attestation.PredicateType == "https://github.com/npm/attestation/tree/main/specs/publish/v0.1" {
			status.Attestation, status.ProvenanceError = v.verifyAttestation(attestation.Bundle, digest)
		}

		if attestation.PredicateType == "https://slsa.dev/provenance/v1" {
			status.Provenance, status.ProvenanceError = v.verifyProvenance(attestation.Bundle, digest)
		}
	}

	return status, nil
}

// Verification logic taken from:
// https://github.com/sigstore/sigstore-go/blob/main/docs/verification.md
func (v *Verifier) verifyAttestation(bundle *bundle.Bundle, digest []byte) (*verify.VerificationResult, error) {
	result, err := v.NPMPublicKey.Verify(
		bundle,
		verify.NewPolicy(
			verify.WithArtifactDigest("sha512", digest),
			verify.WithKey(),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("verifying a bundle: %w", err)
	}

	return result, nil
}

func (v *Verifier) verifyProvenance(bundle *bundle.Bundle, digest []byte) (*verify.VerificationResult, error) {
	// TODO: check specific cert identities
	result, err := v.SigStore.Verify(
		bundle,
		verify.NewPolicy(
			verify.WithArtifactDigest("sha512", digest),
			verify.WithoutIdentitiesUnsafe(),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("verifying a bundle: %w", err)
	}

	return result, nil
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
