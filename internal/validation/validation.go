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

// FlatCertDERs returns leaf + chain certificates as a flat []byte slice of
// DER encodings, skipping nil entries. Order is: leaf first, then chain.
func (m *TrustMaterial) FlatCertDERs() [][]byte {
	if m == nil {
		return nil
	}
	out := make([][]byte, 0, 1+len(m.Chain))
	if m.Leaf != nil {
		out = append(out, m.Leaf.Raw)
	}
	for _, c := range m.Chain {
		if c == nil {
			continue
		}
		out = append(out, c.Raw)
	}
	return out
}

// FlatCRLDERs returns the DER encodings of every CRL in the material, skipping
// nil entries.
func (m *TrustMaterial) FlatCRLDERs() [][]byte {
	if m == nil {
		return nil
	}
	out := make([][]byte, 0, len(m.CRLs))
	for _, crl := range m.CRLs {
		if crl == nil {
			continue
		}
		out = append(out, crl.Raw)
	}
	return out
}
