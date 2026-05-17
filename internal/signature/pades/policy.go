package pades

import (
	"crypto"
	"crypto/x509"
	"signer-engine/internal/signature/cms"
	"signer-engine/internal/signature/signaturepolicy"
)

// SigningContext holds the context available when building PAdES signed attributes.
type SigningContext struct {
	Certificate *x509.Certificate
	Chain       []*x509.Certificate
	HashAlg     crypto.Hash
}

// Policy defines the requirements for a PAdES signature policy.
// It extends the base signaturepolicy.Policy with PAdES-specific behavior.
type Policy interface {
	signaturepolicy.Policy
	// SignedAttributes returns the CMS signed attributes required by the policy.
	SignedAttributes(ctx SigningContext) ([]cms.Attribute, error)
}
