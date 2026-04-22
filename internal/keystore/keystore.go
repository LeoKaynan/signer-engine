package keystore

import (
	"crypto"
	"crypto/x509"
)

type Store interface {
	Open() error
	GetSigner(alias string) (Signer, error)
	Close() error
}

type Signer interface {
	Sign(digest []byte, opts crypto.SignerOpts) ([]byte, error)
	Certificate() *x509.Certificate
	Chain() []*x509.Certificate
}
