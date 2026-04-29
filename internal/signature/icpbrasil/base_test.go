package icpbrasil

import (
	"crypto/x509"
	"signer-engine/internal/testutil/certfixture"
	"testing"
)

func TestValidateSigningCertificate_ValidFakeICPBrasilCertificate(t *testing.T) {
	chain := certfixture.NewChain(t,
		certfixture.WithICPBrasilPolicy(),
	)

	base := newICPBrasilBaseWithRootsPEM(certificateToPEM(chain.Root))

	if err := base.ValidateSigningCertificate(chain.Leaf, chain.Chain); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestValidateSigningCertificate_RejectsMissingICPBrasilPolicy(t *testing.T) {
	chain := certfixture.NewChain(t)

	base := newICPBrasilBaseWithRootsPEM(certificateToPEM(chain.Root))

	if err := base.ValidateSigningCertificate(chain.Leaf, chain.Chain); err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestValidateSigningCertificate_RejectsMissingDigitalSignatureUsage(t *testing.T) {
	chain := certfixture.NewChain(t,
		certfixture.WithICPBrasilPolicy(),
		certfixture.WithLeaf(func(template *x509.Certificate) {
			template.KeyUsage = x509.KeyUsageKeyEncipherment
		}),
	)

	base := newICPBrasilBaseWithRootsPEM(certificateToPEM(chain.Root))

	if err := base.ValidateSigningCertificate(chain.Leaf, chain.Chain); err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestValidateSigningCertificate_RejectsUntrustedRoot(t *testing.T) {
	chain := certfixture.NewChain(t,
		certfixture.WithICPBrasilPolicy(),
	)

	base := newICPBrasilBaseWithRootsPEM(nil)

	if err := base.ValidateSigningCertificate(chain.Leaf, chain.Chain); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func newICPBrasilBaseWithRootsPEM(rootsPEM []byte) icpBrasilBase {
	return icpBrasilBase{
		rootPEM: func() ([]byte, error) {
			return rootsPEM, nil
		},
	}
}
