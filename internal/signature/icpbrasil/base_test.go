package icpbrasil

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

var (
	testOIDCPF       = asn1.ObjectIdentifier{2, 16, 76, 1, 3, 1}
	testOIDPolicyICP = asn1.ObjectIdentifier{2, 16, 76, 1, 2, 1}
	// RFC5280
	oidExtensionCertificatePolicies = asn1.ObjectIdentifier{2, 5, 29, 32}
)

type policyInformation struct {
	PolicyIdentifier asn1.ObjectIdentifier
}

func TestValidadeSigningCertificate_ValidFakeICPBrasilCertificate(t *testing.T) {
	leaf, chain, roots := newFakeICPBrasilChain(t, func(template *x509.Certificate) {})

	base := icpBrasilBase{
		rootPool: func() (*x509.CertPool, error) {
			return roots, nil
		},
	}

	if err := base.ValidateSigningCertificate(leaf, chain); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func newFakeICPBrasilChain(
	t *testing.T,
	mutateLeaf func(template *x509.Certificate),
) (*x509.Certificate, []*x509.Certificate, *x509.CertPool) {
	t.Helper()

	now := time.Now()

	rootKey := newRSAKey(t)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "fake ICP-Brasil root CA",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	root := createCertificate(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)

	intermediateKey := newRSAKey(t)
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "fake ICP-Brasil intermediate CA",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen:            0,
	}

	intermediate := createCertificate(t, intermediateTemplate, root, &intermediateKey.PublicKey, rootKey)

	leafKey := newRSAKey(t)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "fake ICP-Brasil leaf certificate",
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  testOIDCPF,
					Value: "12345678901",
				},
			},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			mustCertificatePoliciesExtension(t, testOIDPolicyICP),
		},
	}

	mutateLeaf(leafTemplate)

	leaf := createCertificate(t, leafTemplate, intermediate, &leafKey.PublicKey, intermediateKey)

	roots := x509.NewCertPool()
	roots.AddCert(root)

	return leaf, []*x509.Certificate{intermediate}, roots
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	return key
}

func createCertificate(
	t *testing.T,
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

func mustCertificatePoliciesExtension(t *testing.T, oid asn1.ObjectIdentifier) pkix.Extension {
	t.Helper()

	der, err := asn1.Marshal([]policyInformation{
		{
			PolicyIdentifier: oid,
		},
	})
	if err != nil {
		t.Fatalf("failed to marshal certificate policies extension: %v", err)
	}

	return pkix.Extension{
		Id:    oidExtensionCertificatePolicies,
		Value: der,
	}
}
