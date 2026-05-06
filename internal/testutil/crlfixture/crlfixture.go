package crlfixture

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

type Fixture struct {
	Now          time.Time
	Root         *x509.Certificate
	RootKey      *rsa.PrivateKey
	Intermediate *x509.Certificate
	InterKey     *rsa.PrivateKey
	Leaf         *x509.Certificate
	LeafCRL      *x509.RevocationList
}

func New(t testing.TB, crlDistributionPoints ...string) Fixture {
	t.Helper()

	now := time.Date(2026, 5, 4, 0, 0, 0, 0, time.UTC)

	rootKey := NewRSAKey(t)
	root := CreateCertificate(t, CertConfig{
		Serial:    big.NewInt(1),
		Subject:   "root",
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(24 * time.Hour),
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, nil, &rootKey.PublicKey, rootKey)

	interKey := NewRSAKey(t)
	intermediate := CreateCertificate(t, CertConfig{
		Serial:    big.NewInt(2),
		Subject:   "intermediate",
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(24 * time.Hour),
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, root, &interKey.PublicKey, rootKey)

	leafKey := NewRSAKey(t)
	leaf := CreateCertificate(t, CertConfig{
		Serial:                big.NewInt(3),
		Subject:               "leaf",
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		CRLDistributionPoints: crlDistributionPoints,
	}, intermediate, &leafKey.PublicKey, interKey)

	return Fixture{
		Now:          now,
		Root:         root,
		RootKey:      rootKey,
		Intermediate: intermediate,
		InterKey:     interKey,
		Leaf:         leaf,
		LeafCRL:      CreateCRL(t, intermediate, interKey, leaf.SerialNumber, now),
	}
}

func CloneCertificateWithAIAAndCRL(t testing.TB, fixture Fixture, issuerURL string, crlURL string) *x509.Certificate {
	t.Helper()

	key := NewRSAKey(t)
	return CreateCertificate(t, CertConfig{
		Serial:                big.NewInt(30),
		Subject:               "leaf-with-aia",
		NotBefore:             fixture.Now.Add(-time.Hour),
		NotAfter:              fixture.Now.Add(24 * time.Hour),
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		IssuingCertificateURL: []string{issuerURL},
		CRLDistributionPoints: []string{crlURL},
	}, fixture.Intermediate, &key.PublicKey, fixture.InterKey)
}

func (f Fixture) NowFunc() func() time.Time {
	return func() time.Time {
		return f.Now.Add(10 * time.Minute)
	}
}

type CertConfig struct {
	Serial    *big.Int
	Subject   string
	NotBefore time.Time
	NotAfter  time.Time
	IsCA      bool
	KeyUsage  x509.KeyUsage

	IssuingCertificateURL []string
	CRLDistributionPoints []string
}

func CreateCertificate(t testing.TB, cfg CertConfig, issuer *x509.Certificate, publicKey any, issuerKey any) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber:          cfg.Serial,
		Subject:               pkix.Name{CommonName: cfg.Subject},
		NotBefore:             cfg.NotBefore,
		NotAfter:              cfg.NotAfter,
		IsCA:                  cfg.IsCA,
		BasicConstraintsValid: true,
		KeyUsage:              cfg.KeyUsage,
		IssuingCertificateURL: cfg.IssuingCertificateURL,
		CRLDistributionPoints: cfg.CRLDistributionPoints,
	}

	if issuer == nil {
		issuer = template
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuer, publicKey, issuerKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	return cert
}

func CreateCRL(t testing.TB, issuer *x509.Certificate, issuerKey crypto.Signer, revokedSerial *big.Int, now time.Time) *x509.RevocationList {
	t.Helper()

	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		SignatureAlgorithm: x509.SHA256WithRSA,
		Number:             big.NewInt(10),
		ThisUpdate:         now,
		NextUpdate:         now.Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   revokedSerial,
				RevocationTime: now,
			},
		},
	}, issuer, issuerKey)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}

	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}

	return crl
}

func NewRSAKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	return key
}
