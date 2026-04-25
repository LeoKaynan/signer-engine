package cms

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
)

type Policy interface {
	Identifier() asn1.ObjectIdentifier
	SignedAttributes() []Attribute
	ValidateSigningCertificate(certificate *x509.Certificate) error
	MandatedHashAlg() crypto.Hash
}
