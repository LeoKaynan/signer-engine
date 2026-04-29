package certfixture

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"signer-engine/internal/signer"
	"testing"
)

var _ signer.Credential = Credential{}

type Credential struct {
	PrivateKey crypto.Signer
	Cert       *x509.Certificate
	CertChain  []*x509.Certificate
}

func NewCredential(t testing.TB, opts ...Option) Credential {
	t.Helper()

	chain := NewChain(t, opts...)
	return Credential{
		PrivateKey: chain.LeafKey,
		Cert:       chain.Leaf,
		CertChain:  chain.Chain,
	}
}

func (c Credential) Sign(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return c.PrivateKey.Sign(rand.Reader, digest, opts)
}

func (c Credential) Certificate() *x509.Certificate {
	return c.Cert
}

func (c Credential) Chain() []*x509.Certificate {
	return c.CertChain
}
