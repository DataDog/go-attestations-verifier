package httputil

import (
	"net/http"
	"time"
)

const defaultTimeout = 10 * time.Second

func DefaultClient() *http.Client {
	return &http.Client{
		Timeout: defaultTimeout,
	}
}
