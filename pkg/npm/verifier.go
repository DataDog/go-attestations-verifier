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

	"github.com/DataDog/go-attestations-verifier/internal/httputil"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
)

type Verifier struct {
	NPM           *Client
	SigStore      *verify.Verifier
	NPMPublicKeys []*verify.Verifier
}

func NewVerifier(ctx context.Context, npm *Client) (*Verifier, error) {
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

	npmPublicKeys, err := NewNPMPublicKeyVerifiers(ctx, npm, trustedRoot)
	if err != nil {
		return nil, err
	}

	return &Verifier{
		NPM:           npm,
		SigStore:      sigstore,
		NPMPublicKeys: npmPublicKeys,
	}, nil
}

type VerificationStatus struct {
	URL              string
	SHA512           string
	InferredIssuer   string
	HasAttestations  bool
	Attestation      *verify.VerificationResult
	AttestationError error
	Provenance       *verify.VerificationResult
	ProvenanceError  error
}

//nolint:cyclop
func (v *Verifier) Verify(ctx context.Context, pkg *PackageVersion) (*VerificationStatus, error) {
	encodedDigest, ok := strings.CutPrefix(pkg.Dist.Integrity, "sha512-")
	if !ok {
		return nil, ErrMissingSHA512Digest
	}

	source, err := httputil.ParseSourceURL(pkg.Repository.URL)
	if err != nil {
		return nil, fmt.Errorf("parsing source url: %w", err)
	}

	certID, err := httputil.GetCertID(source)
	if err != nil {
		return nil, fmt.Errorf("inferring certificate id: %w", err)
	}

	digest, err := base64.StdEncoding.DecodeString(encodedDigest)
	if err != nil {
		return nil, fmt.Errorf("decoding base64 encoded package's version sha512: %w", err)
	}

	status := &VerificationStatus{
		URL:            pkg.Dist.Tarball,
		SHA512:         encodedDigest,
		InferredIssuer: httputil.IssuerByHost[source.Host],
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
			status.Attestation, status.AttestationError = v.verifyAttestation(attestation.Bundle, digest)
		}

		if attestation.PredicateType == "https://slsa.dev/provenance/v1" {
			status.Provenance, status.ProvenanceError = v.SigStore.Verify(
				attestation.Bundle,
				verify.NewPolicy(
					verify.WithArtifactDigest("sha512", digest),
					certID,
				),
			)
		}
	}

	return status, nil
}

// Verification logic taken from:
// https://github.com/sigstore/sigstore-go/blob/main/docs/verification.md
func (v *Verifier) verifyAttestation(bundle *bundle.Bundle, digest []byte) (*verify.VerificationResult, error) {
	var lastErr error

	for keyIndex, verifier := range v.NPMPublicKeys {
		result, err := verifier.Verify(
			bundle,
			verify.NewPolicy(
				verify.WithArtifactDigest("sha512", digest),
				verify.WithKey(),
			),
		)
		if err != nil {
			lastErr = fmt.Errorf("verifying bundle with key %d: %w", keyIndex, err)

			continue
		}

		return result, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("verifying bundle failed with all public keys, last error: %w", lastErr)
	}

	return nil, ErrNoPublicKeysVerifiers
}

func NewNPMPublicKeyVerifiers(
	ctx context.Context,
	npm *Client,
	trustedRoot *root.TrustedRoot,
) ([]*verify.Verifier, error) {
	publicKeys, err := npm.GetPublicKeys(ctx)
	if err != nil {
		return nil, err
	}

	if len(publicKeys) == 0 {
		return nil, ErrMissingPublicKeys
	}

	verifiers := make([]*verify.Verifier, 0, len(publicKeys))

	for keyIndex, key := range publicKeys {
		publicKeyBytes, err := base64.StdEncoding.DecodeString(key.Key)
		if err != nil {
			return nil, fmt.Errorf("decoding base64 encoded public key %d: %w", keyIndex, err)
		}

		publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("parsing public key %d: %w", keyIndex, err)
		}

		verifier, err := signature.LoadVerifier(publicKey, crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("loading verifier for key %d: %w", keyIndex, err)
		}

		sev, err := verify.NewVerifier(&verifyTrustedMaterial{
			TrustedMaterial: trustedRoot,
			keyTrustedMaterial: root.NewTrustedPublicKeyMaterial(func(_ string) (root.TimeConstrainedVerifier, error) {
				return root.NewExpiringKey(verifier, time.Time{}, time.Time{}), nil
			}),
		}, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
		if err != nil {
			return nil, fmt.Errorf("creating new verifier for key %d: %w", keyIndex, err)
		}

		verifiers = append(verifiers, sev)
	}

	return verifiers, nil
}

type verifyTrustedMaterial struct {
	root.TrustedMaterial

	keyTrustedMaterial root.TrustedMaterial
}

//nolint:ireturn
func (v *verifyTrustedMaterial) PublicKeyVerifier(hint string) (root.TimeConstrainedVerifier, error) {
	tcv, err := v.keyTrustedMaterial.PublicKeyVerifier(hint)
	if err != nil {
		return nil, fmt.Errorf("creating a time constrained verifier: %w", err)
	}

	return tcv, nil
}
