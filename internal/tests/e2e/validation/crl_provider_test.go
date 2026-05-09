package validation_test

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"signer-engine/internal/tests/fixtures"
	"signer-engine/internal/tests/utils"
	"signer-engine/internal/validation"
)

func TestCRLTrustMaterialExtractorUsesProvidedCRL(t *testing.T) {
	chain := fixtures.NewChain(t)
	crl := fixtures.NewCRL(t, chain)
	extractor := validation.CRLTrustMaterialExtractor{
		CRLs: []*x509.RevocationList{crl},
		Now:  nowFunc(),
	}

	material, err := extractor.FromCertificate(context.Background(), chain.Leaf, chain.Intermediates())
	if err != nil {
		t.Fatalf("FromCertificate failed: %v", err)
	}
	if material.Leaf == nil {
		t.Fatal("expected leaf certificate")
	}
	if len(material.Chain) != 1 {
		t.Fatalf("expected one chain certificate, got %d", len(material.Chain))
	}
	if len(material.CRLs) != 1 {
		t.Fatalf("expected one CRL, got %d", len(material.CRLs))
	}
}

func TestCRLTrustMaterialExtractorFetchesAndCachesCRL(t *testing.T) {
	var crlDER []byte
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(crlDER)
	}))
	defer server.Close()

	chain := fixtures.NewChain(t, fixtures.WithLeafCRLDistributionPoints(server.URL+"/leaf.crl"))
	crlDER = fixtures.NewCRL(t, chain).Raw
	extractor := validation.CRLTrustMaterialExtractor{
		HTTPClient: server.Client(),
		CacheDir:   t.TempDir(),
		Now:        nowFunc(),
	}

	for range 2 {
		material, err := extractor.FromCertificate(context.Background(), chain.Leaf, chain.Intermediates())
		if err != nil {
			t.Fatalf("FromCertificate failed: %v", err)
		}
		if len(material.CRLs) != 1 {
			t.Fatalf("expected one CRL, got %d", len(material.CRLs))
		}
	}
	if calls != 1 {
		t.Fatalf("expected one CRL HTTP request due to cache, got %d", calls)
	}
}

func TestCRLTrustMaterialExtractorDiscoversIssuerFromAIA(t *testing.T) {
	var issuerDER []byte
	var crlDER []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/issuer.cer":
			w.Header().Set("Content-Type", "application/pkix-cert")
			_, _ = w.Write(issuerDER)
		case "/leaf.crl":
			w.Header().Set("Content-Type", "application/pkix-crl")
			_, _ = w.Write(crlDER)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	chain := fixtures.NewChain(t,
		fixtures.WithLeafIssuingCertificateURLs(server.URL+"/issuer.cer"),
		fixtures.WithLeafCRLDistributionPoints(server.URL+"/leaf.crl"),
	)
	issuerDER = chain.Intermediate.Raw
	crlDER = fixtures.NewCRL(t, chain).Raw

	extractor := validation.CRLTrustMaterialExtractor{
		HTTPClient: server.Client(),
		CacheDir:   t.TempDir(),
		Now:        nowFunc(),
	}
	material, err := extractor.FromCertificate(context.Background(), chain.Leaf, nil)
	if err != nil {
		t.Fatalf("FromCertificate failed: %v", err)
	}
	if len(material.Chain) != 1 {
		t.Fatalf("expected discovered issuer in chain, got %d", len(material.Chain))
	}
	if len(material.CRLs) != 1 {
		t.Fatalf("expected one CRL, got %d", len(material.CRLs))
	}
}

func TestCRLTrustMaterialExtractorRejectsInvalidRevocationMaterial(t *testing.T) {
	chain := fixtures.NewChain(t)
	now := time.Now().UTC()

	tests := []struct {
		name       string
		extractor  validation.CRLTrustMaterialExtractor
		wantErrSub string
	}{
		{
			name: "missing CRL",
			extractor: validation.CRLTrustMaterialExtractor{
				Now: nowFunc(),
			},
			wantErrSub: "no matching CRL found for certificate chain",
		},
		{
			name: "invalid CRL signature",
			extractor: validation.CRLTrustMaterialExtractor{
				CRLs: []*x509.RevocationList{
					fixtures.NewCRLForCertificateSignedBy(
						t,
						chain.Intermediate,
						chain.RootKey,
						chain.Leaf.SerialNumber,
						now.Add(-time.Minute),
						now.Add(time.Hour),
					),
				},
				Now: nowFunc(),
			},
			wantErrSub: "failed to verify CRL signature",
		},
		{
			name: "expired CRL",
			extractor: validation.CRLTrustMaterialExtractor{
				CRLs: []*x509.RevocationList{
					fixtures.NewCRLForCertificate(
						t,
						chain.Intermediate,
						chain.IntermediateKey,
						chain.Leaf.SerialNumber,
						now.Add(-2*time.Hour),
						now.Add(-time.Hour),
					),
				},
				Now: nowFunc(),
			},
			wantErrSub: "CRL expired",
		},
		{
			name: "future thisUpdate",
			extractor: validation.CRLTrustMaterialExtractor{
				CRLs: []*x509.RevocationList{
					fixtures.NewCRLForCertificate(
						t,
						chain.Intermediate,
						chain.IntermediateKey,
						chain.Leaf.SerialNumber,
						now.Add(time.Hour),
						now.Add(2*time.Hour),
					),
				},
				Now: nowFunc(),
			},
			wantErrSub: "CRL thisUpdate is in the future",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.extractor.FromCertificate(context.Background(), chain.Leaf, chain.Intermediates())
			utils.RequireErrorContains(t, err, tt.wantErrSub)
		})
	}
}

func nowFunc() func() time.Time {
	return func() time.Time {
		return time.Now().UTC()
	}
}
