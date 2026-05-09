package validation

import (
	"context"
	"crypto/x509"
)

type TrustMaterialExtractor interface {
	FromCertificate(
		ctx context.Context,
		leaf *x509.Certificate,
		chain []*x509.Certificate,
	) (*TrustMaterial, error)
	FromTimestampToken(ctx context.Context, tokenDER []byte) (*TrustMaterial, error)
}

type TrustMaterial struct {
	Leaf  *x509.Certificate
	Chain []*x509.Certificate
	CRLs  []*x509.RevocationList
}
