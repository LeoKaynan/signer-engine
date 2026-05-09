package cades

import (
	"crypto/x509"
	"encoding/asn1"
	"testing"

	"signer-engine/internal/testutil/crlfixture"
)

func TestBuildCertificateRefs(t *testing.T) {
	fixture := crlfixture.New(t)

	refsDER, err := BuildCertificateRefs([]*x509.Certificate{fixture.Intermediate})
	if err != nil {
		t.Fatalf("BuildCertificateRefs failed: %v", err)
	}

	var refs []otherCertID
	if rest, err := asn1.Unmarshal(refsDER, &refs); err != nil || len(rest) != 0 {
		t.Fatalf("unmarshal certificate refs: rest=%x err=%v", rest, err)
	}
	if len(refs) != 1 {
		t.Fatalf("expected one certificate ref, got %d", len(refs))
	}
	if len(refs[0].OtherCertHash.HashAlgorithm.Parameters.FullBytes) != 0 {
		t.Fatal("expected certificate refs SHA-256 algorithm identifier without parameters")
	}
}

func TestBuildCertificateValues(t *testing.T) {
	fixture := crlfixture.New(t)

	valuesDER, err := BuildCertificateValues([]*x509.Certificate{fixture.Intermediate})
	if err != nil {
		t.Fatalf("BuildCertificateValues failed: %v", err)
	}

	var values []asn1.RawValue
	if rest, err := asn1.Unmarshal(valuesDER, &values); err != nil || len(rest) != 0 {
		t.Fatalf("unmarshal certificate values: rest=%x err=%v", rest, err)
	}
	if len(values) != 1 {
		t.Fatalf("expected one certificate value, got %d", len(values))
	}
}

func TestBuildRevocationRefsUsesOneCrlOcspRefPerCRL(t *testing.T) {
	fixture := crlfixture.New(t)
	rootCRL := crlfixture.CreateCRL(t, fixture.Root, fixture.RootKey, fixture.Intermediate.SerialNumber, fixture.Now)

	refsDER, err := BuildRevocationRefs([]*x509.RevocationList{fixture.LeafCRL, rootCRL})
	if err != nil {
		t.Fatalf("BuildRevocationRefs failed: %v", err)
	}

	var refs []crlOcspRef
	if rest, err := asn1.Unmarshal(refsDER, &refs); err != nil || len(rest) != 0 {
		t.Fatalf("unmarshal revocation refs: rest=%x err=%v", rest, err)
	}
	if len(refs) != 2 {
		t.Fatalf("expected one CrlOcspRef per CRL, got %d", len(refs))
	}
	for i, ref := range refs {
		if len(ref.CRLIDs.CRLs) != 1 {
			t.Fatalf("expected CrlOcspRef %d to contain one CRL, got %d", i, len(ref.CRLIDs.CRLs))
		}
	}
	if len(refs[0].CRLIDs.CRLs[0].CRLHash.HashAlgorithm.Parameters.FullBytes) != 0 {
		t.Fatal("expected revocation refs SHA-256 algorithm identifier without parameters")
	}
}

func TestBuildRevocationValues(t *testing.T) {
	fixture := crlfixture.New(t)

	valuesDER, err := BuildRevocationValues([]*x509.RevocationList{fixture.LeafCRL})
	if err != nil {
		t.Fatalf("BuildRevocationValues failed: %v", err)
	}

	var values revocationValues
	if rest, err := asn1.Unmarshal(valuesDER, &values); err != nil || len(rest) != 0 {
		t.Fatalf("unmarshal revocation values: rest=%x err=%v", rest, err)
	}
	if len(values.CRLVals) != 1 {
		t.Fatalf("expected one revocation value, got %d", len(values.CRLVals))
	}
}
