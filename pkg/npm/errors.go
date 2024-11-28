package npm

import "errors"

var (
	ErrMissingSHA512Digest = errors.New("sha512 digest not found for package's version")
	ErrMissingPublicKeys   = errors.New("no public keys returned by NPM")
)
