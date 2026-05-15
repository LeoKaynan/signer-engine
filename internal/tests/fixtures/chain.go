package fixtures

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"
)

var (
	OIDICPBrasilTest              = asn1.ObjectIdentifier{2, 16, 76, 1, 2, 1}
	oidExtensionCertificatePolicy = asn1.ObjectIdentifier{2, 5, 29, 32}
)

type Chain struct {
	Leaf            *x509.Certificate
	LeafKey         *rsa.PrivateKey
	Intermediate    *x509.Certificate
	IntermediateKey *rsa.PrivateKey
	Root            *x509.Certificate
	RootKey         *rsa.PrivateKey
	RootPEM         []byte
	IntermediatePEM []byte
}

type ChainOption func(*chainConfig)

type chainConfig struct {
	now                    time.Time
	leafNotBefore          time.Time
	leafNotAfter           time.Time
	leafKeyUsage           x509.KeyUsage
	includeICPBrasilPolicy bool
	leafIssuingCertURLs    []string
	leafCRLDistributionPts []string
	leafSerial             *big.Int
}

func WithExpiredLeaf() ChainOption {
	return func(c *chainConfig) {
		c.leafNotBefore = c.now.Add(-48 * time.Hour)
		c.leafNotAfter = c.now.Add(-24 * time.Hour)
	}
}

func WithLeafSerialNumber(serial *big.Int) ChainOption {
	return func(c *chainConfig) {
		c.leafSerial = serial
	}
}

func WithoutDigitalSignatureKeyUsage() ChainOption {
	return func(c *chainConfig) {
		c.leafKeyUsage = 0
	}
}

func WithoutICPBrasilPolicy() ChainOption {
	return func(c *chainConfig) {
		c.includeICPBrasilPolicy = false
	}
}

func WithLeafIssuingCertificateURLs(urls ...string) ChainOption {
	return func(c *chainConfig) {
		c.leafIssuingCertURLs = append([]string(nil), urls...)
	}
}

func WithLeafCRLDistributionPoints(urls ...string) ChainOption {
	return func(c *chainConfig) {
		c.leafCRLDistributionPts = append([]string(nil), urls...)
	}
}

func NewChain(t testing.TB, opts ...ChainOption) Chain {
	t.Helper()

	now := time.Now().UTC()
	cfg := chainConfig{
		now:                    now,
		leafNotBefore:          now.Add(-time.Hour),
		leafNotAfter:           now.Add(24 * time.Hour),
		leafKeyUsage:           x509.KeyUsageDigitalSignature,
		includeICPBrasilPolicy: true,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	rootKey := newRSAKey(t)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "signer-engine-e2e-root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	root := createCertificate(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)

	intermediateKey := newRSAKey(t)
	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "signer-engine-e2e-intermediate"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen:            0,
	}
	intermediate := createCertificate(t, intermediateTemplate, root, &intermediateKey.PublicKey, rootKey)

	leafSerial := big.NewInt(3)
	if cfg.leafSerial != nil {
		leafSerial = cfg.leafSerial
	}

	leafKey := newRSAKey(t)
	leafTemplate := &x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               pkix.Name{CommonName: "signer-engine-e2e-leaf"},
		NotBefore:             cfg.leafNotBefore,
		NotAfter:              cfg.leafNotAfter,
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              cfg.leafKeyUsage,
		IssuingCertificateURL: cfg.leafIssuingCertURLs,
		CRLDistributionPoints: cfg.leafCRLDistributionPts,
	}
	if cfg.includeICPBrasilPolicy {
		leafTemplate.ExtraExtensions = []pkix.Extension{
			certificatePoliciesExtension(t, OIDICPBrasilTest),
		}
	}
	leaf := createCertificate(t, leafTemplate, intermediate, &leafKey.PublicKey, intermediateKey)

	return Chain{
		Leaf:            leaf,
		LeafKey:         leafKey,
		Intermediate:    intermediate,
		IntermediateKey: intermediateKey,
		Root:            root,
		RootKey:         rootKey,
		RootPEM:         certificateToPEM(root),
		IntermediatePEM: certificateToPEM(intermediate),
	}
}

func (c Chain) Intermediates() []*x509.Certificate {
	return []*x509.Certificate{c.Intermediate}
}

func newRSAKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return key
}

func createCertificate(
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

type policyInformation struct {
	PolicyIdentifier asn1.ObjectIdentifier
}

func certificatePoliciesExtension(t testing.TB, policies ...asn1.ObjectIdentifier) pkix.Extension {
	t.Helper()

	policyInfos := make([]policyInformation, 0, len(policies))
	for _, policy := range policies {
		policyInfos = append(policyInfos, policyInformation{PolicyIdentifier: policy})
	}

	der, err := asn1.Marshal(policyInfos)
	if err != nil {
		t.Fatalf("failed to marshal certificate policies: %v", err)
	}

	return pkix.Extension{
		Id:    oidExtensionCertificatePolicy,
		Value: der,
	}
}

func certificateToPEM(cert *x509.Certificate) []byte {
	if cert == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

func (c Chain) Validate(t testing.TB) {
	t.Helper()

	if c.Leaf == nil || c.LeafKey == nil || c.Intermediate == nil || c.IntermediateKey == nil || c.Root == nil || c.RootKey == nil {
		t.Fatal("chain is incomplete")
	}
	if len(c.RootPEM) == 0 {
		t.Fatal("root PEM is empty")
	}
	if len(c.IntermediatePEM) == 0 {
		t.Fatal("intermediate PEM is empty")
	}
	if err := c.Leaf.CheckSignatureFrom(c.Intermediate); err != nil {
		t.Fatalf("leaf signature is invalid: %v", err)
	}
	if err := c.Intermediate.CheckSignatureFrom(c.Root); err != nil {
		t.Fatalf("intermediate signature is invalid: %v", err)
	}
}

func (c Chain) String() string {
	return fmt.Sprintf("%s -> %s -> %s", c.Leaf.Subject.CommonName, c.Intermediate.Subject.CommonName, c.Root.Subject.CommonName)
}
