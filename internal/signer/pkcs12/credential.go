package pkcs12

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
)

type credential struct {
	privateKey  crypto.Signer
	certificate *x509.Certificate
	chain       []*x509.Certificate
}

func newCredential(privateKey crypto.Signer, certificate *x509.Certificate, chain []*x509.Certificate) *credential {
	return &credential{
		privateKey:  privateKey,
		certificate: certificate,
		chain:       chain,
	}
}

func (c *credential) Sign(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return c.privateKey.Sign(rand.Reader, digest, opts)
}

func (c *credential) Certificate() *x509.Certificate {
	return c.certificate
}

func (c *credential) Chain() []*x509.Certificate {
	return c.chain
}
