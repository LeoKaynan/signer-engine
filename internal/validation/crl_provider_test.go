package validation

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"signer-engine/internal/testutil/crlfixture"
	"strings"
	"testing"
	"time"
)

func TestCRLTrustMaterialExtractorFromCertificate(t *testing.T) {
	fixture := crlfixture.New(t)
	extractor := CRLTrustMaterialExtractor{
		CRLs: []*x509.RevocationList{fixture.LeafCRL},
		Now:  fixture.NowFunc(),
	}

	material, err := extractor.FromCertificate(
		context.Background(),
		fixture.Leaf,
		[]*x509.Certificate{fixture.Intermediate},
	)
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

func TestCRLTrustMaterialExtractorFromCertificateFetchesCRLFromDistributionPoint(t *testing.T) {
	var crlDER []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(crlDER)
	}))
	defer server.Close()

	fixture := crlfixture.New(t, server.URL+"/leaf.crl")
	crlDER = fixture.LeafCRL.Raw
	extractor := CRLTrustMaterialExtractor{
		HTTPClient: server.Client(),
		CacheDir:   t.TempDir(),
		Now:        fixture.NowFunc(),
	}

	material, err := extractor.FromCertificate(
		context.Background(),
		fixture.Leaf,
		[]*x509.Certificate{fixture.Intermediate},
	)
	if err != nil {
		t.Fatalf("FromCertificate failed: %v", err)
	}
	if len(material.CRLs) == 0 {
		t.Fatal("expected revocation material")
	}
}

func TestCRLTrustMaterialExtractorFromCertificateDiscoversIssuerFromAIA(t *testing.T) {
	fixture := crlfixture.New(t)

	var leafCRLDER []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/issuer.cer":
			w.Header().Set("Content-Type", "application/pkix-cert")
			_, _ = w.Write(fixture.Intermediate.Raw)
		case "/leaf.crl":
			w.Header().Set("Content-Type", "application/pkix-crl")
			_, _ = w.Write(leafCRLDER)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	leaf := crlfixture.CloneCertificateWithAIAAndCRL(
		t,
		fixture,
		server.URL+"/issuer.cer",
		server.URL+"/leaf.crl",
	)
	leafCRL := crlfixture.CreateCRL(t, fixture.Intermediate, fixture.InterKey, leaf.SerialNumber, fixture.Now)
	leafCRLDER = leafCRL.Raw

	extractor := CRLTrustMaterialExtractor{
		HTTPClient: server.Client(),
		CacheDir:   t.TempDir(),
		Now:        fixture.NowFunc(),
	}

	material, err := extractor.FromCertificate(context.Background(), leaf, nil)
	if err != nil {
		t.Fatalf("FromCertificate failed: %v", err)
	}
	if len(material.Chain) != 1 {
		t.Fatalf("expected discovered issuer in chain, got %d", len(material.Chain))
	}
	if len(material.CRLs) == 0 {
		t.Fatal("expected revocation material")
	}
}

func TestCRLTrustMaterialExtractorFromCertificateUsesCachedCRL(t *testing.T) {
	var calls int
	var crlDER []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(crlDER)
	}))
	defer server.Close()

	fixture := crlfixture.New(t, server.URL+"/leaf.crl")
	crlDER = fixture.LeafCRL.Raw
	extractor := CRLTrustMaterialExtractor{
		HTTPClient: server.Client(),
		CacheDir:   t.TempDir(),
		Now:        fixture.NowFunc(),
	}

	for range 2 {
		_, err := extractor.FromCertificate(
			context.Background(),
			fixture.Leaf,
			[]*x509.Certificate{fixture.Intermediate},
		)
		if err != nil {
			t.Fatalf("FromCertificate failed: %v", err)
		}
	}

	if calls != 1 {
		t.Fatalf("expected one CRL HTTP request, got %d", calls)
	}
}

func TestCRLTrustMaterialExtractorFromCertificateRequiresDistributionPointOrProvidedCRL(t *testing.T) {
	fixture := crlfixture.New(t)
	extractor := CRLTrustMaterialExtractor{Now: fixture.NowFunc()}

	_, err := extractor.FromCertificate(
		context.Background(),
		fixture.Leaf,
		[]*x509.Certificate{fixture.Intermediate},
	)
	if err == nil {
		t.Fatal("expected missing CRL distribution point error")
	}
	if !strings.Contains(err.Error(), "no matching CRL found for certificate chain") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCRLTrustMaterialExtractorFromCertificateRejectsInvalidCRLSignature(t *testing.T) {
	fixture := crlfixture.New(t)
	invalidCRL := crlfixture.CreateCRL(
		t,
		fixture.Intermediate,
		fixture.RootKey,
		fixture.Leaf.SerialNumber,
		fixture.Now,
	)
	extractor := CRLTrustMaterialExtractor{
		CRLs: []*x509.RevocationList{invalidCRL},
		Now:  fixture.NowFunc(),
	}

	_, err := extractor.FromCertificate(
		context.Background(),
		fixture.Leaf,
		[]*x509.Certificate{fixture.Intermediate},
	)
	if err == nil {
		t.Fatal("expected invalid CRL signature error")
	}
	if !strings.Contains(err.Error(), "failed to verify CRL signature") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCRLTrustMaterialExtractorFromCertificateRejectsExpiredCRL(t *testing.T) {
	fixture := crlfixture.New(t)
	extractor := CRLTrustMaterialExtractor{
		CRLs: []*x509.RevocationList{fixture.LeafCRL},
		Now: func() time.Time {
			return fixture.LeafCRL.NextUpdate.Add(time.Minute)
		},
	}

	_, err := extractor.FromCertificate(
		context.Background(),
		fixture.Leaf,
		[]*x509.Certificate{fixture.Intermediate},
	)
	if err == nil {
		t.Fatal("expected expired CRL error")
	}
	if !strings.Contains(err.Error(), "CRL expired") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCRLTrustMaterialExtractorFromCertificateRejectsFutureThisUpdate(t *testing.T) {
	fixture := crlfixture.New(t)
	extractor := CRLTrustMaterialExtractor{
		CRLs: []*x509.RevocationList{fixture.LeafCRL},
		Now: func() time.Time {
			return fixture.LeafCRL.ThisUpdate.Add(-time.Minute)
		},
	}

	_, err := extractor.FromCertificate(
		context.Background(),
		fixture.Leaf,
		[]*x509.Certificate{fixture.Intermediate},
	)
	if err == nil {
		t.Fatal("expected future thisUpdate error")
	}
	if !strings.Contains(err.Error(), "CRL thisUpdate is in the future") {
		t.Fatalf("unexpected error: %v", err)
	}
}
