package signer

import (
	"crypto"
	"crypto/x509"
)

type Credential interface {
	Sign(digest []byte, opts crypto.SignerOpts) ([]byte, error)
	Certificate() *x509.Certificate
	Chain() []*x509.Certificate
}
