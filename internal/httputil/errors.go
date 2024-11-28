package httputil

import "fmt"

type HTTPStatusError struct {
	StatusCode int
	Body       string
}

func (h *HTTPStatusError) Error() string {
	return fmt.Sprintf("http error with status code %d: %s", h.StatusCode, h.Body)
}
