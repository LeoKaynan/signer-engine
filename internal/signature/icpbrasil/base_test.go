package icpbrasil

import (
	"crypto/x509"
	"signer-engine/internal/testutil/certfixture"
	"testing"
)

func TestValidateSigningCertificate_ValidFakeICPBrasilCertificate(t *testing.T) {
	chain := certfixture.NewChain(t,
		certfixture.WithCPF("12345678901"),
		certfixture.WithICPBrasilPolicy(),
	)

	base := newICPBrasilBaseWithRoots(chain.Roots)

	if err := base.ValidateSigningCertificate(chain.Leaf, chain.Chain); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestValidateSigningCertificate_RejectsMissingICPBrasilPolicy(t *testing.T) {
	chain := certfixture.NewChain(t, certfixture.WithCPF("12345678901"))

	base := newICPBrasilBaseWithRoots(chain.Roots)

	if err := base.ValidateSigningCertificate(chain.Leaf, chain.Chain); err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestValidateSigningCertificate_RejectsMissingDigitalSignatureUsage(t *testing.T) {
	chain := certfixture.NewChain(t,
		certfixture.WithCPF("12345678901"),
		certfixture.WithICPBrasilPolicy(),
		certfixture.WithLeaf(func(template *x509.Certificate) {
			template.KeyUsage = x509.KeyUsageKeyEncipherment
		}),
	)

	base := newICPBrasilBaseWithRoots(chain.Roots)

	if err := base.ValidateSigningCertificate(chain.Leaf, chain.Chain); err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestValidateSigningCertificate_RejectsUntrustedRoot(t *testing.T) {
	chain := certfixture.NewChain(t,
		certfixture.WithCPF("12345678901"),
		certfixture.WithICPBrasilPolicy(),
	)

	base := newICPBrasilBaseWithRoots(x509.NewCertPool())

	if err := base.ValidateSigningCertificate(chain.Leaf, chain.Chain); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestValidateSigningCertificate_RejectsMissingCPFOrCNPJ(t *testing.T) {
	chain := certfixture.NewChain(t, certfixture.WithICPBrasilPolicy())

	base := newICPBrasilBaseWithRoots(chain.Roots)

	if err := base.ValidateSigningCertificate(chain.Leaf, chain.Chain); err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func newICPBrasilBaseWithRoots(roots *x509.CertPool) icpBrasilBase {
	return icpBrasilBase{
		rootPool: func() (*x509.CertPool, error) {
			return roots, nil
		},
	}
}
