package rekor

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protosigstore "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	rekorbpb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	rekorClient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/tle"
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

type Client struct {
	Rekor *rekorClient.Rekor
}

//nolint:funlen
func (c *Client) GetBundle(ctx context.Context, digest []byte) (*bundle.Bundle, error) {
	hash := "sha256:" + hex.EncodeToString(digest)

	indexSearchQuery := index.NewSearchIndexParamsWithContext(ctx)
	indexSearchQuery.SetQuery(&models.SearchIndex{Hash: hash})

	searchResponse, err := c.Rekor.Index.SearchIndex(indexSearchQuery)
	if err != nil {
		return nil, fmt.Errorf("searching rekor index: %w", err)
	}

	uuids := searchResponse.GetPayload()
	if len(uuids) == 0 {
		return nil, ErrNoRekorLogEntry
	}

	entryGetRequest := entries.NewGetLogEntryByUUIDParamsWithContext(ctx)
	entryGetRequest.SetEntryUUID(uuids[0])

	resp, err := c.Rekor.Entries.GetLogEntryByUUID(entryGetRequest)
	if err != nil {
		return nil, fmt.Errorf("getting rekor log entry by uuid: %w", err)
	}

	var anon models.LogEntryAnon
	for _, v := range resp.Payload {
		anon = v

		break
	}

	tle, err := tle.GenerateTransparencyLogEntry(anon)
	if err != nil {
		return nil, fmt.Errorf("generating transparency log entry: %w", err)
	}

	certificate, signature, err := c.extractBundleContent(anon)
	if err != nil {
		return nil, fmt.Errorf("extracting bundle content from rekor entry: %w", err)
	}

	protoBundle := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			TlogEntries: []*rekorbpb.TransparencyLogEntry{tle},
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protosigstore.X509Certificate{RawBytes: certificate},
			},
		},
		Content: &protobundle.Bundle_MessageSignature{
			MessageSignature: &protosigstore.MessageSignature{
				Signature: signature,
				MessageDigest: &protosigstore.HashOutput{
					Algorithm: protosigstore.HashAlgorithm_SHA2_256,
					Digest:    digest,
				},
			},
		},
	}

	b, err := bundle.NewBundle(protoBundle)
	if err != nil {
		return nil, fmt.Errorf("creating bundle: %w", err)
	}

	return b, nil
}

func (c *Client) extractBundleContent(anon models.LogEntryAnon) ([]byte, []byte, error) {
	bodyStr, ok := anon.Body.(string)
	if !ok {
		return nil, nil, ErrRekorEntryBodyIsNil
	}

	bodyBytes, err := base64.StdEncoding.DecodeString(bodyStr)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding base64 encoded rekor entry body: %w", err)
	}

	var rekorEntry models.Hashedrekord

	err = json.Unmarshal(bodyBytes, &rekorEntry)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing a protojson encoded rekor transparency log entry: %w", err)
	}

	spec, err := json.Marshal(rekorEntry.Spec)
	if err != nil {
		return nil, nil, fmt.Errorf("marshalling rekor entry spec: %w", err)
	}

	var hasherRekorEntry models.HashedrekordV001Schema

	err = json.Unmarshal(spec, &hasherRekorEntry)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshalling rekor entry spec: %w", err)
	}

	publicKey, err := base64.StdEncoding.DecodeString(hasherRekorEntry.Signature.PublicKey.Content.String())
	if err != nil {
		return nil, nil, fmt.Errorf("decoding base64 encoded public key: %w", err)
	}

	cert, _ := pem.Decode(publicKey)

	signature, err := base64.StdEncoding.DecodeString(hasherRekorEntry.Signature.Content.String())
	if err != nil {
		return nil, nil, fmt.Errorf("decoding base64 encoded signature: %w", err)
	}

	return cert.Bytes, signature, nil
}
