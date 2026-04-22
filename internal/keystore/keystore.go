package keystore

import (
	"context"
	"crypto"
	"crypto/x509"
)

type Store interface {
	Open(ctx context.Context) error
	GetSigner(ctx context.Context, alias string) (Signer, error)
	Close(ctx context.Context) error
}

type Signer interface {
	Sign(digest []byte, opts crypto.SignerOpts) ([]byte, error)
	Certificate() *x509.Certificate
	Chain() []*x509.Certificate
}
