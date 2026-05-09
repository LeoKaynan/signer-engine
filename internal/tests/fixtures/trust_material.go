package fixtures

import (
	"context"
	"crypto/x509"
	"testing"

	"signer-engine/internal/validation"
)

type TrustMaterialExtractor struct {
	t testing.TB

	SignerCRLs    []*x509.RevocationList
	TimestampCRLs []*x509.RevocationList

	CertificateCalls    int
	TimestampTokenCalls int
}

func NewTrustMaterialExtractor(t testing.TB, chain Chain) *TrustMaterialExtractor {
	t.Helper()

	crl := NewCRL(t, chain)
	return &TrustMaterialExtractor{
		t:             t,
		SignerCRLs:    []*x509.RevocationList{crl},
		TimestampCRLs: []*x509.RevocationList{crl},
	}
}

func (e *TrustMaterialExtractor) FromCertificate(ctx context.Context, leaf *x509.Certificate, chain []*x509.Certificate) (*validation.TrustMaterial, error) {
	e.t.Helper()

	e.CertificateCalls++

	return &validation.TrustMaterial{
		Leaf:  leaf,
		Chain: append([]*x509.Certificate(nil), chain...),
		CRLs:  append([]*x509.RevocationList(nil), e.SignerCRLs...),
	}, nil
}

func (e *TrustMaterialExtractor) FromTimestampToken(ctx context.Context, tokenDER []byte) (*validation.TrustMaterial, error) {
	e.t.Helper()

	e.TimestampTokenCalls++
	return &validation.TrustMaterial{
		CRLs: append([]*x509.RevocationList(nil), e.TimestampCRLs...),
	}, nil
}
