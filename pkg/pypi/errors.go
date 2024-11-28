package pypi

import "errors"

var ErrMissingReleases = errors.New("no releases for this project's version")
