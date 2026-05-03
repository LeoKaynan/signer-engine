package cades

import (
	"crypto"
	"crypto/x509"
	"signer-engine/internal/signature/cms"
	"signer-engine/internal/signature/signaturepolicy"
)

type PolicyName string

type SigningContext struct {
	Certificate *x509.Certificate
	Chain       []*x509.Certificate
	HashAlg     crypto.Hash
	Detached    bool
}

type Policy interface {
	signaturepolicy.Policy
	SignedAttributes(ctx SigningContext) ([]cms.Attribute, error)
	UnsignedAttributeNames() []AttributeName
}
