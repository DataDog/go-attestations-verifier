package rekor_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/DataDog/go-attestations-verifier/pkg/rekor"
	runtimeclient "github.com/go-openapi/runtime/client"
	rekorclient "github.com/sigstore/rekor/pkg/generated/client"
)

func TestGetBundleRequestErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		cancelPath     string
		searchResponse string
		wantError      error
	}{
		{
			name:           "index search canceled",
			cancelPath:     "/api/v1/index/retrieve",
			searchResponse: `["entry"]`,
			wantError:      context.Canceled,
		},
		{
			name:           "log entry retrieval canceled",
			cancelPath:     "/api/v1/log/entries/entry",
			searchResponse: `["entry"]`,
			wantError:      context.Canceled,
		},
		{
			name:           "no matching log entry",
			searchResponse: `[]`,
			wantError:      rekor.ErrNoRekorLogEntry,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			transport := runtimeclient.New("rekor.test", "/", []string{"https"})
			transport.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.Path == test.cancelPath {
					cancel()

					return nil, request.Context().Err()
				}

				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": {"application/json"}},
					Body:       io.NopCloser(strings.NewReader(test.searchResponse)),
				}, nil
			})
			client := rekor.Client{Rekor: rekorclient.New(transport, nil)}

			_, err := client.GetBundle(ctx, []byte("digest"))
			if !errors.Is(err, test.wantError) {
				t.Fatalf("GetBundle() error = %v, want %v", err, test.wantError)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}
