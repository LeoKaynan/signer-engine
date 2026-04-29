package certfixture

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

type Chain struct {
	Leaf         *x509.Certificate
	LeafKey      *rsa.PrivateKey
	Intermediate *x509.Certificate
	Root         *x509.Certificate
	Roots        *x509.CertPool
	Chain        []*x509.Certificate
}

type Option func(*config)

type config struct {
	now        time.Time
	mutateLeaf func(*x509.Certificate)
}

func NewChain(t testing.TB, opts ...Option) Chain {
	t.Helper()

	cfg := config{now: time.Now()}
	for _, opt := range opts {
		opt(&cfg)
	}

	rootKey := NewRSAKey(t)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "signer-engine-test-root"},
		NotBefore:             cfg.now.Add(-time.Hour),
		NotAfter:              cfg.now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	root := CreateCertificate(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)

	intermediateKey := NewRSAKey(t)
	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "signer-engine-test-intermediate"},
		NotBefore:             cfg.now.Add(-time.Hour),
		NotAfter:              cfg.now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen:            0,
	}
	intermediate := CreateCertificate(t, intermediateTemplate, root, &intermediateKey.PublicKey, rootKey)

	leafKey := NewRSAKey(t)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "signer-engine-test-leaf"},
		NotBefore:             cfg.now.Add(-time.Hour),
		NotAfter:              cfg.now.Add(24 * time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}

	if cfg.mutateLeaf != nil {
		cfg.mutateLeaf(leafTemplate)
	}

	leaf := CreateCertificate(t, leafTemplate, intermediate, &leafKey.PublicKey, intermediateKey)

	roots := x509.NewCertPool()
	roots.AddCert(root)

	return Chain{
		Leaf:         leaf,
		LeafKey:      leafKey,
		Intermediate: intermediate,
		Root:         root,
		Roots:        roots,
		Chain:        []*x509.Certificate{intermediate},
	}
}

func WithCurrentTime(now time.Time) Option {
	return func(cfg *config) {
		cfg.now = now
	}
}

func WithLeaf(mutator func(*x509.Certificate)) Option {
	return func(cfg *config) {
		previous := cfg.mutateLeaf
		cfg.mutateLeaf = func(template *x509.Certificate) {
			if previous != nil {
				previous(template)
			}
			mutator(template)
		}
	}
}

func WithCPF(cpf string) Option {
	return WithSubjectName(OIDSubjectCPF, cpf)
}

func WithCNPJ(cnpj string) Option {
	return WithSubjectName(OIDSubjectCNPJ, cnpj)
}

func WithSubjectName(oid asn1.ObjectIdentifier, value string) Option {
	return func(cfg *config) {
		previous := cfg.mutateLeaf
		cfg.mutateLeaf = func(template *x509.Certificate) {
			if previous != nil {
				previous(template)
			}
			template.Subject.ExtraNames = append(template.Subject.ExtraNames, pkix.AttributeTypeAndValue{
				Type:  oid,
				Value: value,
			})
		}
	}
}

func WithCertificatePolicies(policies ...asn1.ObjectIdentifier) Option {
	return func(cfg *config) {
		previous := cfg.mutateLeaf
		cfg.mutateLeaf = func(template *x509.Certificate) {
			if previous != nil {
				previous(template)
			}
			extension, err := certificatePoliciesExtension(policies...)
			if err != nil {
				panic(err)
			}
			template.ExtraExtensions = append(
				template.ExtraExtensions,
				extension,
			)
		}
	}
}

func WithICPBrasilPolicy() Option {
	return WithCertificatePolicies(OIDICPBrasilTest)
}

func NewRSAKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	return key
}

func CreateCertificate(
	t testing.TB,
	template *x509.Certificate,
	parent *x509.Certificate,
	publicKey any,
	parentPrivateKey any,
) *x509.Certificate {
	t.Helper()

	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		parent,
		publicKey,
		parentPrivateKey,
	)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}
