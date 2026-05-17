package pades_test

import (
	"bytes"
	"testing"
	"time"

	"signer-engine/internal/app/signing"
	"signer-engine/internal/signature/pades"
	"signer-engine/internal/signature/signaturepolicy"
	"signer-engine/internal/tests/fixtures"
)


func padesPolicyResolver(t testing.TB, ltvLevel signaturepolicy.Level) signing.PAdESPolicyResolver {
	t.Helper()
	return func(_ signaturepolicy.PolicyName) (pades.Policy, error) {
		return fixtures.NewPAdESPolicy(t, ltvLevel), nil
	}
}

func newPAdESTestService(t testing.TB, ltvLevel signaturepolicy.Level) signing.Service {
	t.Helper()
	return signing.Service{
		Deps: signing.SignerDeps{
			Clock: func() time.Time { return fixtures.DefaultSigningTime },
		},
		SignerFactories: map[signing.Format]signing.SignerFactory{
			signing.FormatPades: signing.NewPAdESSignerFactory(padesPolicyResolver(t, ltvLevel)),
		},
		CredentialResolvers: map[signing.CredentialProvider]signing.CredentialResolver{
			signing.CredentialProviderPKCS12: signing.NewPKCS12CredentialResolver(),
		},
	}
}

func newService(t testing.TB, ltvLevel signaturepolicy.Level) signing.Service {
	return newPAdESTestService(t, ltvLevel)
}

func newTimestampService(t testing.TB, ltvLevel signaturepolicy.Level) (signing.Service, *fixtures.TimeStampProvider) {
	t.Helper()
	tsp := fixtures.NewTimeStampProvider(t)
	svc := newPAdESTestService(t, ltvLevel)
	svc.Deps.TimeStampProvider = tsp
	return svc, tsp
}

func newDSSService(t testing.TB, ltvLevel signaturepolicy.Level) (signing.Service, *fixtures.TimeStampProvider, *fixtures.TrustMaterialExtractor) {
	t.Helper()
	chain := fixtures.NewChain(t)
	tsp := fixtures.NewTimeStampProvider(t)
	tme := fixtures.NewTrustMaterialExtractor(t, chain)
	svc := newPAdESTestService(t, ltvLevel)
	svc.Deps.TimeStampProvider = tsp
	svc.Deps.TrustMaterialExtractor = tme
	return svc, tsp, tme
}

func assertSignedPDF(t testing.TB, signed []byte) {
	t.Helper()
	if !bytes.HasPrefix(signed, []byte("%PDF")) {
		t.Error("signed output does not start with %PDF")
	}
	if !bytes.Contains(signed, []byte("/ByteRange")) {
		t.Error("expected /ByteRange in signed PDF")
	}
	if !bytes.Contains(signed, []byte("/Contents")) {
		t.Error("expected /Contents in signed PDF")
	}
	if !bytes.Contains(signed, []byte("/DocMDP")) {
		t.Error("expected /DocMDP (first signature certification) in signed PDF")
	}
	if !bytes.Contains(signed, []byte("/Perms")) {
		t.Error("expected /Perms in signed PDF")
	}
	if !bytes.Contains(signed, []byte("/T (Signature2)")) {
		t.Error("expected reserved field Signature2 in signed PDF")
	}
}

func TestPKCS12PAdESADRB(t *testing.T) {
	chain := fixtures.NewChain(t)
	p12 := fixtures.NewPKCS12(t, chain, fixtures.DefaultPKCS12Password)
	pdf := fixtures.MinimalPDF()
	svc := newService(t, signaturepolicy.LevelB)

	response, err := svc.Sign(signing.Request{
		Data:               pdf,
		CredentialProvider: signing.CredentialProviderPKCS12,
		PKCS12Data:         p12,
		PKCS12Pass:         fixtures.DefaultPKCS12Password,
		Format:             signing.FormatPades,
		Policy:             "PA_AD_RB",
	})
	if err != nil {
		t.Fatalf("Sign PAdES AD-RB: %v", err)
	}

	assertSignedPDF(t, response.Signature)
}

func TestPKCS12PAdESADRT(t *testing.T) {
	chain := fixtures.NewChain(t)
	p12 := fixtures.NewPKCS12(t, chain, fixtures.DefaultPKCS12Password)
	pdf := fixtures.MinimalPDF()
	svc, tsp := newTimestampService(t, signaturepolicy.LevelT)

	response, err := svc.Sign(signing.Request{
		Data:               pdf,
		CredentialProvider: signing.CredentialProviderPKCS12,
		PKCS12Data:         p12,
		PKCS12Pass:         fixtures.DefaultPKCS12Password,
		Format:             signing.FormatPades,
		Policy:             "PA_AD_RT",
	})
	if err != nil {
		t.Fatalf("Sign PAdES AD-RT: %v", err)
	}

	assertSignedPDF(t, response.Signature)

	if len(tsp.Inputs) != 1 {
		t.Fatalf("expected 1 timestamp request, got %d", len(tsp.Inputs))
	}
}

func TestPKCS12PAdESADRC(t *testing.T) {
	chain := fixtures.NewChain(t)
	p12 := fixtures.NewPKCS12(t, chain, fixtures.DefaultPKCS12Password)
	pdf := fixtures.MinimalPDF()
	svc, tsp, tme := newDSSService(t, signaturepolicy.LevelC)

	response, err := svc.Sign(signing.Request{
		Data:               pdf,
		CredentialProvider: signing.CredentialProviderPKCS12,
		PKCS12Data:         p12,
		PKCS12Pass:         fixtures.DefaultPKCS12Password,
		Format:             signing.FormatPades,
		Policy:             "PA_AD_RC",
	})
	if err != nil {
		t.Fatalf("Sign PAdES AD-RC: %v", err)
	}

	assertSignedPDF(t, response.Signature)

	if tme.CertificateCalls != 1 {
		t.Errorf("expected 1 FromCertificate call, got %d", tme.CertificateCalls)
	}
	// 1 signature timestamp (embedded in CMS) + 1 DocTimeStamp
	if len(tsp.Inputs) != 2 {
		t.Errorf("expected 2 timestamp requests (signature timestamp + DocTimeStamp), got %d", len(tsp.Inputs))
	}
	if !bytes.Contains(response.Signature, []byte("/DSS")) {
		t.Error("expected /DSS in signed PDF")
	}
	if !bytes.Contains(response.Signature, []byte("DocTimeStamp")) {
		t.Error("expected DocTimeStamp field in signed PDF")
	}
}

func TestPKCS12PAdESADRA(t *testing.T) {
	chain := fixtures.NewChain(t)
	p12 := fixtures.NewPKCS12(t, chain, fixtures.DefaultPKCS12Password)
	pdf := fixtures.MinimalPDF()
	svc, tsp, tme := newDSSService(t, signaturepolicy.LevelA)

	response, err := svc.Sign(signing.Request{
		Data:               pdf,
		CredentialProvider: signing.CredentialProviderPKCS12,
		PKCS12Data:         p12,
		PKCS12Pass:         fixtures.DefaultPKCS12Password,
		Format:             signing.FormatPades,
		Policy:             "PA_AD_RA",
	})
	if err != nil {
		t.Fatalf("Sign PAdES AD-RA: %v", err)
	}

	assertSignedPDF(t, response.Signature)

	if tme.CertificateCalls != 1 {
		t.Errorf("expected 1 FromCertificate call, got %d", tme.CertificateCalls)
	}
	// 1 signature timestamp (embedded in CMS) + 1 DocTimeStamp + 1 ArchiveTimeStamp
	if len(tsp.Inputs) != 3 {
		t.Errorf("expected 3 timestamp requests (signature timestamp + DocTimeStamp + ArchiveTimeStamp), got %d", len(tsp.Inputs))
	}
	if !bytes.Contains(response.Signature, []byte("/DSS")) {
		t.Error("expected /DSS in signed PDF")
	}
	if !bytes.Contains(response.Signature, []byte("DocTimeStamp")) {
		t.Error("expected DocTimeStamp field in signed PDF")
	}
	if !bytes.Contains(response.Signature, []byte("ArchiveTimeStamp")) {
		t.Error("expected ArchiveTimeStamp field in signed PDF")
	}
}

func TestPKCS12PAdESSerialSigningADRB(t *testing.T) {
	chain := fixtures.NewChain(t)
	p12 := fixtures.NewPKCS12(t, chain, fixtures.DefaultPKCS12Password)
	pdf := fixtures.MinimalPDF()
	svc := newService(t, signaturepolicy.LevelB)

	first, err := svc.Sign(signing.Request{
		Data:               pdf,
		CredentialProvider: signing.CredentialProviderPKCS12,
		PKCS12Data:         p12,
		PKCS12Pass:         fixtures.DefaultPKCS12Password,
		Format:             signing.FormatPades,
		Policy:             "PA_AD_RB",
	})
	if err != nil {
		t.Fatalf("first Sign PAdES: %v", err)
	}
	assertSignedPDF(t, first.Signature)
	if !bytes.Contains(first.Signature, []byte("/T (Signature2)")) {
		t.Fatal("expected Signature2 reserved field after first signature")
	}

	// Auto-detect: feeding the signed PDF back routes to serial signing.
	second, err := svc.Sign(signing.Request{
		Data:               first.Signature,
		CredentialProvider: signing.CredentialProviderPKCS12,
		PKCS12Data:         p12,
		PKCS12Pass:         fixtures.DefaultPKCS12Password,
		Format:             signing.FormatPades,
		Policy:             "PA_AD_RB",
	})
	if err != nil {
		t.Fatalf("serial Sign PAdES: %v", err)
	}
	if !bytes.HasPrefix(second.Signature, []byte("%PDF")) {
		t.Fatal("expected serial output to start with %PDF")
	}
	if bytes.Count(second.Signature, []byte("/Contents <")) < 2 {
		t.Errorf("expected at least 2 /Contents entries (initial sig + serial), got %d", bytes.Count(second.Signature, []byte("/Contents <")))
	}
	if bytes.Count(second.Signature, []byte("/SubFilter /adbe.pkcs7.detached")) < 2 {
		t.Error("expected serial PDF to carry two PAdES signature subfilters")
	}
	// DocMDP must remain anchored to the FIRST signature only.
	if bytes.Count(second.Signature, []byte("/DocMDP")) != bytes.Count(first.Signature, []byte("/DocMDP")) {
		t.Error("serial signing should not add new DocMDP entries")
	}
}

func TestPKCS12PAdESSerialSigningADRT(t *testing.T) {
	chain := fixtures.NewChain(t)
	p12 := fixtures.NewPKCS12(t, chain, fixtures.DefaultPKCS12Password)
	pdf := fixtures.MinimalPDF()
	svc, tsp := newTimestampService(t, signaturepolicy.LevelT)

	first, err := svc.Sign(signing.Request{
		Data:               pdf,
		CredentialProvider: signing.CredentialProviderPKCS12,
		PKCS12Data:         p12,
		PKCS12Pass:         fixtures.DefaultPKCS12Password,
		Format:             signing.FormatPades,
		Policy:             "PA_AD_RT",
	})
	if err != nil {
		t.Fatalf("first Sign PAdES AD-RT: %v", err)
	}
	if len(tsp.Inputs) != 1 {
		t.Fatalf("expected 1 TSP call for first sig, got %d", len(tsp.Inputs))
	}

	second, err := svc.Sign(signing.Request{
		Data:               first.Signature,
		CredentialProvider: signing.CredentialProviderPKCS12,
		PKCS12Data:         p12,
		PKCS12Pass:         fixtures.DefaultPKCS12Password,
		Format:             signing.FormatPades,
		Policy:             "PA_AD_RT",
	})
	if err != nil {
		t.Fatalf("serial Sign PAdES AD-RT: %v", err)
	}
	if len(tsp.Inputs) != 2 {
		t.Fatalf("expected 2 TSP calls after serial sig (one per signature), got %d", len(tsp.Inputs))
	}
	if bytes.Count(second.Signature, []byte("/Contents <")) < 2 {
		t.Error("expected at least 2 /Contents in serial AD-RT PDF")
	}
}

func TestPKCS12PAdESSerialSigningADRCRejected(t *testing.T) {
	chain := fixtures.NewChain(t)
	p12 := fixtures.NewPKCS12(t, chain, fixtures.DefaultPKCS12Password)
	pdf := fixtures.MinimalPDF()
	svc, _, _ := newDSSService(t, signaturepolicy.LevelC)

	first, err := svc.Sign(signing.Request{
		Data:               pdf,
		CredentialProvider: signing.CredentialProviderPKCS12,
		PKCS12Data:         p12,
		PKCS12Pass:         fixtures.DefaultPKCS12Password,
		Format:             signing.FormatPades,
		Policy:             "PA_AD_RC",
	})
	if err != nil {
		t.Fatalf("first Sign PAdES AD-RC: %v", err)
	}

	_, err = svc.Sign(signing.Request{
		Data:               first.Signature,
		CredentialProvider: signing.CredentialProviderPKCS12,
		PKCS12Data:         p12,
		PKCS12Pass:         fixtures.DefaultPKCS12Password,
		Format:             signing.FormatPades,
		Policy:             "PA_AD_RC",
	})
	if err == nil {
		t.Fatal("expected serial AD-RC to fail until DSS-merge is implemented")
	}
}
