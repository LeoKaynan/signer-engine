package validation

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"net/http"
	"net/http/httptest"
	"signer-engine/internal/testutil/crlfixture"
	"strings"
	"testing"
	"time"
)

func TestCRLProviderBuildRefs(t *testing.T) {
	fixture := crlfixture.New(t)
	provider := CRLProvider{
		CRLs: []*x509.RevocationList{fixture.LeafCRL},
		Now:  fixture.NowFunc(),
	}

	refs, err := provider.BuildRefs(
		context.Background(),
		fixture.Leaf,
		[]*x509.Certificate{fixture.Intermediate},
	)
	if err != nil {
		t.Fatalf("BuildRefs failed: %v", err)
	}

	var certificateRefs []otherCertID
	if rest, err := asn1.Unmarshal(refs.CertificateRefs, &certificateRefs); err != nil || len(rest) != 0 {
		t.Fatalf("unmarshal certificate refs: rest=%x err=%v", rest, err)
	}
	if len(certificateRefs) != 1 {
		t.Fatalf("expected one certificate ref, got %d", len(certificateRefs))
	}

	var revocationRefs []crlOcspRef
	if rest, err := asn1.Unmarshal(refs.RevocationRefs, &revocationRefs); err != nil || len(rest) != 0 {
		t.Fatalf("unmarshal revocation refs: rest=%x err=%v", rest, err)
	}
	if len(revocationRefs) != 1 || len(revocationRefs[0].CRLIDs.CRLs) != 1 {
		t.Fatalf("expected one CRL ref, got %+v", revocationRefs)
	}

	if len(certificateRefs[0].OtherCertHash.HashAlgorithm.Parameters.FullBytes) != 0 {
		t.Fatal("expected certificate refs SHA-256 algorithm identifier without parameters")
	}
	if len(revocationRefs[0].CRLIDs.CRLs[0].CRLHash.HashAlgorithm.Parameters.FullBytes) != 0 {
		t.Fatal("expected revocation refs SHA-256 algorithm identifier without parameters")
	}

	var certificateValues []asn1.RawValue
	if rest, err := asn1.Unmarshal(refs.CertificateValues, &certificateValues); err != nil || len(rest) != 0 {
		t.Fatalf("unmarshal certificate values: rest=%x err=%v", rest, err)
	}
	if len(certificateValues) != 1 {
		t.Fatalf("expected one certificate value, got %d", len(certificateValues))
	}

	var revocationValues revocationValues
	if rest, err := asn1.Unmarshal(refs.RevocationValues, &revocationValues); err != nil || len(rest) != 0 {
		t.Fatalf("unmarshal revocation values: rest=%x err=%v", rest, err)
	}
	if len(revocationValues.CRLVals) != 1 {
		t.Fatalf("expected one revocation value, got %d", len(revocationValues.CRLVals))
	}
}

func TestCRLProviderBuildRevocationRefsUsesOneCrlOcspRefPerCRL(t *testing.T) {
	fixture := crlfixture.New(t)
	rootCRL := crlfixture.CreateCRL(t, fixture.Root, fixture.RootKey, fixture.Intermediate.SerialNumber, fixture.Now)
	provider := CRLProvider{
		CRLs: []*x509.RevocationList{fixture.LeafCRL, rootCRL},
		Now:  fixture.NowFunc(),
	}

	revocationRefsDER, err := provider.BuildRevocationRefs(
		context.Background(),
		fixture.Leaf,
		[]*x509.Certificate{fixture.Intermediate, fixture.Root},
	)
	if err != nil {
		t.Fatalf("BuildRevocationRefs failed: %v", err)
	}

	var revocationRefs []crlOcspRef
	if rest, err := asn1.Unmarshal(revocationRefsDER, &revocationRefs); err != nil || len(rest) != 0 {
		t.Fatalf("unmarshal revocation refs: rest=%x err=%v", rest, err)
	}
	if len(revocationRefs) != 2 {
		t.Fatalf("expected one CrlOcspRef per CRL, got %d", len(revocationRefs))
	}
	for i, ref := range revocationRefs {
		if len(ref.CRLIDs.CRLs) != 1 {
			t.Fatalf("expected CrlOcspRef %d to contain one CRL, got %d", i, len(ref.CRLIDs.CRLs))
		}
	}
}

func TestCRLProviderBuildRefsFetchesCRLFromCertificateDistributionPoint(t *testing.T) {
	var crlDER []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(crlDER)
	}))
	defer server.Close()

	fixture := crlfixture.New(t, server.URL+"/leaf.crl")
	crlDER = fixture.LeafCRL.Raw
	provider := CRLProvider{
		HTTPClient: server.Client(),
		CacheDir:   t.TempDir(),
		Now:        fixture.NowFunc(),
	}

	refs, err := provider.BuildRefs(
		context.Background(),
		fixture.Leaf,
		[]*x509.Certificate{fixture.Intermediate},
	)
	if err != nil {
		t.Fatalf("BuildRefs failed: %v", err)
	}
	if len(refs.RevocationRefs) == 0 {
		t.Fatal("expected revocation refs")
	}
}

func TestCRLProviderBuildRefsDiscoversIssuerFromAIA(t *testing.T) {
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

	provider := CRLProvider{
		HTTPClient: server.Client(),
		CacheDir:   t.TempDir(),
		Now:        fixture.NowFunc(),
	}

	refs, err := provider.BuildRefs(context.Background(), leaf, nil)
	if err != nil {
		t.Fatalf("BuildRefs failed: %v", err)
	}

	var certificateRefs []otherCertID
	if rest, err := asn1.Unmarshal(refs.CertificateRefs, &certificateRefs); err != nil || len(rest) != 0 {
		t.Fatalf("unmarshal certificate refs: rest=%x err=%v", rest, err)
	}
	if len(certificateRefs) != 1 {
		t.Fatalf("expected discovered issuer in certificate refs, got %d", len(certificateRefs))
	}
	if len(refs.RevocationRefs) == 0 {
		t.Fatal("expected revocation refs")
	}
}

func TestCRLProviderBuildRefsUsesCachedCRL(t *testing.T) {
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
	provider := CRLProvider{
		HTTPClient: server.Client(),
		CacheDir:   t.TempDir(),
		Now:        fixture.NowFunc(),
	}

	for range 2 {
		_, err := provider.BuildRefs(
			context.Background(),
			fixture.Leaf,
			[]*x509.Certificate{fixture.Intermediate},
		)
		if err != nil {
			t.Fatalf("BuildRefs failed: %v", err)
		}
	}

	if calls != 1 {
		t.Fatalf("expected one CRL HTTP request, got %d", calls)
	}
}

func TestCRLProviderBuildRefsRequiresDistributionPointOrProvidedCRL(t *testing.T) {
	fixture := crlfixture.New(t)
	provider := CRLProvider{Now: fixture.NowFunc()}

	_, err := provider.BuildRefs(
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

func TestCRLProviderBuildRefsRejectsInvalidCRLSignature(t *testing.T) {
	fixture := crlfixture.New(t)
	invalidCRL := crlfixture.CreateCRL(
		t,
		fixture.Intermediate,
		fixture.RootKey,
		fixture.Leaf.SerialNumber,
		fixture.Now,
	)
	provider := CRLProvider{
		CRLs: []*x509.RevocationList{invalidCRL},
		Now:  fixture.NowFunc(),
	}

	_, err := provider.BuildRefs(
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

func TestCRLProviderBuildRefsRejectsExpiredCRL(t *testing.T) {
	fixture := crlfixture.New(t)
	provider := CRLProvider{
		CRLs: []*x509.RevocationList{fixture.LeafCRL},
		Now: func() time.Time {
			return fixture.LeafCRL.NextUpdate.Add(time.Minute)
		},
	}

	_, err := provider.BuildRefs(
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

func TestCRLProviderBuildRefsRejectsFutureThisUpdate(t *testing.T) {
	fixture := crlfixture.New(t)
	provider := CRLProvider{
		CRLs: []*x509.RevocationList{fixture.LeafCRL},
		Now: func() time.Time {
			return fixture.LeafCRL.ThisUpdate.Add(-time.Minute)
		},
	}

	_, err := provider.BuildRefs(
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
