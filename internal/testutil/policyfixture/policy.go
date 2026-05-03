package policyfixture

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"

	"signer-engine/internal/signature/cades"
	"signer-engine/internal/signature/cms"
)

var _ cades.Policy = Policy{}

type Policy struct {
	OID                 asn1.ObjectIdentifier
	HashAlg             crypto.Hash
	SignedAttrs         []cms.Attribute
	UnsignedAttrs       []cades.AttributeName
	ValidateCertificate func(cert *x509.Certificate, chain []*x509.Certificate) error
}

func (p Policy) Identifier() asn1.ObjectIdentifier {
	if p.OID != nil {
		return p.OID
	}
	return asn1.ObjectIdentifier{1, 2, 3, 4}
}

func (p Policy) ValidateSigningCertificate(cert *x509.Certificate, chain []*x509.Certificate) error {
	if p.ValidateCertificate != nil {
		return p.ValidateCertificate(cert, chain)
	}
	return nil
}

func (p Policy) MandatedHashAlg() crypto.Hash {
	if p.HashAlg != 0 {
		return p.HashAlg
	}
	return crypto.SHA256
}

func (p Policy) SignedAttributes(ctx cades.SigningContext) ([]cms.Attribute, error) {
	return append([]cms.Attribute(nil), p.SignedAttrs...), nil
}

func (p Policy) UnsignedAttributeNames() []cades.AttributeName {
	return append([]cades.AttributeName(nil), p.UnsignedAttrs...)
}
