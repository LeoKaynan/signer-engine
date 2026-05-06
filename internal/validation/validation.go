package validation

import (
	"context"
	"crypto/x509"
)

type Provider interface {
	BuildRefs(
		ctx context.Context,
		cert *x509.Certificate,
		chain []*x509.Certificate,
	) (*Refs, error)
}

type Refs struct {
	CertificateRefs   []byte
	RevocationRefs    []byte
	CertificateValues []byte
	RevocationValues  []byte
}
