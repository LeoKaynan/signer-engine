package icpbrasil

import (
	"crypto/x509"
	"testing"
)

func TestValidateSigningCertificate_ValidFakeICPBrasilCertificate(t *testing.T) {
	leaf, chain, roots := newFakeICPBrasilChain(t, nil)

	base := newTestPolicy(roots)

	if err := base.ValidateSigningCertificate(leaf, chain); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestValidateSigningCertificate_RejectsMissingICPBrasilPolicy(t *testing.T) {
	leaf, chain, roots := newFakeICPBrasilChain(t, func(template *x509.Certificate) {
		template.ExtraExtensions = nil
	})

	base := newTestPolicy(roots)

	if err := base.ValidateSigningCertificate(leaf, chain); err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestValidateSigningCertificate_RejectsMissingDigitalSignatureUsage(t *testing.T) {
	leaf, chain, roots := newFakeICPBrasilChain(t, func(template *x509.Certificate) {
		template.KeyUsage = x509.KeyUsageKeyEncipherment
	})

	base := newTestPolicy(roots)

	if err := base.ValidateSigningCertificate(leaf, chain); err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestValidateSigningCertificate_RejectsUntrustedRoot(t *testing.T) {
	leaf, chain, _ := newFakeICPBrasilChain(t, nil)

	base := newTestPolicy(x509.NewCertPool())

	if err := base.ValidateSigningCertificate(leaf, chain); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestValidateSigningCertificate_RejectsMissingCPFOrCNPJ(t *testing.T) {
	leaf, chain, roots := newFakeICPBrasilChain(t, func(template *x509.Certificate) {
		template.Subject.ExtraNames = nil
	})

	base := newTestPolicy(roots)

	if err := base.ValidateSigningCertificate(leaf, chain); err == nil {
		t.Fatalf("expected error, got nil")
	}
}
