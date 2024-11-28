package httputil

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type config struct {
	client  *http.Client
	headers http.Header
}

type Option func(cfg *config)

func WithClient(client *http.Client) Option {
	return func(cfg *config) {
		cfg.client = client
	}
}

func WithHeader(key, value string) Option {
	return func(cfg *config) {
		cfg.headers.Add(key, value)
	}
}

func Get(ctx context.Context, url url.URL, options ...Option) ([]byte, error) {
	cfg := &config{
		headers: http.Header{},
	}

	for _, option := range options {
		option(cfg)
	}

	if cfg.client == nil {
		cfg.client = DefaultClient()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("preparing http request: %w", err)
	}

	if len(cfg.headers) != 0 {
		req.Header = cfg.headers.Clone()
	}

	res, err := cfg.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending http request: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("reading http response's body: %w", err)
	}

	if res.StatusCode < http.StatusOK || res.StatusCode > http.StatusIMUsed {
		return nil, &HTTPStatusError{
			StatusCode: res.StatusCode,
			Body:       string(body),
		}
	}

	return body, nil
}

func GetJSON(ctx context.Context, url url.URL, out interface{}, options ...Option) error {
	data, err := Get(ctx, url, options...)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("parsing json response: %w", err)
	}

	return nil
}
