package pkcs12

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
)

type signer struct {
	privateKey  crypto.Signer
	certificate *x509.Certificate
	chain       []*x509.Certificate
}

func newSigner(privateKey crypto.Signer, certificate *x509.Certificate, chain []*x509.Certificate) *signer {
	return &signer{
		privateKey:  privateKey,
		certificate: certificate,
		chain:       chain,
	}
}

func (s *signer) Sign(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.privateKey.Sign(rand.Reader, digest, opts)
}

func (s *signer) Certificate() *x509.Certificate {
	return s.certificate
}

func (s *signer) Chain() []*x509.Certificate {
	return s.chain
}
