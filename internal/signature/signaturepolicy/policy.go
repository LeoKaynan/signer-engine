package signaturepolicy

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

type PolicyName string

type Policy interface {
	Identifier() asn1.ObjectIdentifier
	ValidateSigningCertificate(certificate *x509.Certificate, chain []*x509.Certificate) error
	// MandatedHashAlg returns the hash algorithm required by the policy.
	// The second value reports whether the policy mandates a specific algorithm;
	// when false, any algorithm is acceptable.
	MandatedHashAlg() (crypto.Hash, bool)
	// Level returns the AdES signature level required by the policy.
	Level() Level
}

// ValidatePolicyPrerequisites checks that the signing certificate passes the
// policy's validation rules and that hashAlg matches the policy's mandated
// algorithm. A nil policy is a no-op.
func ValidatePolicyPrerequisites(policy Policy, hashAlg crypto.Hash, cert *x509.Certificate, chain []*x509.Certificate) error {
	if policy == nil {
		return nil
	}
	if err := policy.ValidateSigningCertificate(cert, chain); err != nil {
		return fmt.Errorf("failed to validate signing certificate: %w", err)
	}
	if mand, required := policy.MandatedHashAlg(); required && mand != hashAlg {
		return fmt.Errorf("hash algorithm does not match the mandated hash algorithm")
	}
	return nil
}
