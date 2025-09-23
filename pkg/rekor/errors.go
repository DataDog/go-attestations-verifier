package rekor

import "errors"

var (
	ErrNoRekorLogEntry     = errors.New("no rekor log entry key found for digest")
	ErrRekorEntryBodyIsNil = errors.New("rekor entry body is nil")
)
