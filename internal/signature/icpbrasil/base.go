// icpbrasil/base.go (novo)
package icpbrasil

import (
	"crypto"
	"crypto/x509"
)

type icpBrasilBase struct{}

func (icpBrasilBase) ValidateSigningCertificate(cert *x509.Certificate) error {
	// TODO: validar:
	//   - Issuer chain leva à AC Raiz ICP-Brasil
	//   - Subject contém CPF (OID 2.16.76.1.3.1) ou CNPJ (2.16.76.1.3.3)
	//   - certificatePolicies extension contém OID ICP-Brasil (2.16.76.1.2.x)
	return nil
}

func (icpBrasilBase) MandatedHashAlg() crypto.Hash {
	return crypto.SHA256
}
