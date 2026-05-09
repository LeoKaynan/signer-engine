package fixtures

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func NewCRL(t testing.TB, chain Chain) *x509.RevocationList {
	t.Helper()

	now := time.Now().UTC()
	return NewCRLForCertificate(t, chain.Intermediate, chain.IntermediateKey, chain.Leaf.SerialNumber, now.Add(-time.Minute), now.Add(time.Hour))
}

func NewCRLForCertificate(
	t testing.TB,
	issuer *x509.Certificate,
	issuerKey crypto.Signer,
	revokedSerial *big.Int,
	thisUpdate time.Time,
	nextUpdate time.Time,
) *x509.RevocationList {
	t.Helper()

	return newCRL(t, issuer, issuerKey, revokedSerial, thisUpdate, nextUpdate, big.NewInt(10))
}

func NewCRLForCertificateSignedBy(
	t testing.TB,
	issuer *x509.Certificate,
	signerKey crypto.Signer,
	revokedSerial *big.Int,
	thisUpdate time.Time,
	nextUpdate time.Time,
) *x509.RevocationList {
	t.Helper()

	return newCRL(t, issuer, signerKey, revokedSerial, thisUpdate, nextUpdate, big.NewInt(11))
}

func newCRL(
	t testing.TB,
	issuer *x509.Certificate,
	signerKey crypto.Signer,
	revokedSerial *big.Int,
	thisUpdate time.Time,
	nextUpdate time.Time,
	number *big.Int,
) *x509.RevocationList {
	t.Helper()

	der, err := x509.CreateRevocationList(
		rand.Reader,
		&x509.RevocationList{
			SignatureAlgorithm:        x509.SHA256WithRSA,
			Number:                    number,
			ThisUpdate:                thisUpdate,
			NextUpdate:                nextUpdate,
			RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: revokedSerial, RevocationTime: thisUpdate}},
		},
		issuer,
		signerKey,
	)
	if err != nil {
		t.Fatalf("failed to create CRL fixture: %v", err)
	}

	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("failed to parse CRL fixture: %v", err)
	}
	return crl
}
