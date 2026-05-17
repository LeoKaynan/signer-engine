package fixtures

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"testing"

	"signer-engine/internal/signature/cms"
	"signer-engine/internal/signature/pades"
	"signer-engine/internal/signature/signaturepolicy"
)

// testPAdESPolicy is a minimal pades.Policy used in tests.
// It uses a synthetic OID and performs no certificate validation.
type testPAdESPolicy struct {
	level signaturepolicy.Level
}

func (p testPAdESPolicy) Identifier() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 999, 1, 1} // synthetic test OID
}

func (p testPAdESPolicy) ValidateSigningCertificate(_ *x509.Certificate, _ []*x509.Certificate) error {
	return nil
}

func (p testPAdESPolicy) MandatedHashAlg() (crypto.Hash, bool) { return crypto.SHA256, true }

func (p testPAdESPolicy) Level() signaturepolicy.Level { return p.level }

func (p testPAdESPolicy) SignedAttributes(ctx pades.SigningContext) ([]cms.Attribute, error) {
	sigCertAttr, err := cms.SigningCertificateV2Attribute(ctx.Certificate)
	if err != nil {
		return nil, err
	}
	return []cms.Attribute{sigCertAttr}, nil
}

var _ pades.Policy = testPAdESPolicy{}

// NewPAdESPolicy returns a test-only pades.Policy with no real ICP-Brasil OIDs.
func NewPAdESPolicy(_ testing.TB, level signaturepolicy.Level) pades.Policy {
	return testPAdESPolicy{level: level}
}
