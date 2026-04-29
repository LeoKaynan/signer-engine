package signaturepolicy

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
)

type Policy interface {
	Identifier() asn1.ObjectIdentifier
	ValidateSigningCertificate(certificate *x509.Certificate, chain []*x509.Certificate) error
	MandatedHashAlg() crypto.Hash
}
