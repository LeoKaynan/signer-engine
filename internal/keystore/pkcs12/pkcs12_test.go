package pkcs12_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"signer-engine/internal/keystore"
	"signer-engine/internal/keystore/pkcs12"
	"testing"
)

const (
	path     = "../../../testdata/with_chain.p12"
	password = "test"
)

func newOpenedSigner(t *testing.T) keystore.Signer {
	t.Helper()

	store := pkcs12.NewStore(pkcs12.Config{
		Path:     path,
		Password: password,
	})
	if err := store.Open(); err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	signer, err := store.GetSigner()
	if err != nil {
		t.Fatalf("GetSigner failed: %v", err)
	}
	return signer
}

func TestStore_Open_RequiresPath(t *testing.T) {
	store := pkcs12.NewStore(pkcs12.Config{})
	err := store.Open()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestStore_Open_FileNotFound(t *testing.T) {
	store := pkcs12.NewStore(pkcs12.Config{
		Path:     "does-not-exist.p12",
		Password: password,
	})
	err := store.Open()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestStore_Open_WrongPassword(t *testing.T) {
	store := pkcs12.NewStore(pkcs12.Config{
		Path:     path,
		Password: "wrong",
	})
	err := store.Open()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestStore_GetSigner_BeforeOpen(t *testing.T) {
	store := pkcs12.NewStore(pkcs12.Config{
		Path:     path,
		Password: password,
	})
	_, err := store.GetSigner()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestStore_Open_Valid(t *testing.T) {
	store := pkcs12.NewStore(pkcs12.Config{
		Path:     path,
		Password: password,
	})
	if err := store.Open(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestSigner_Certificate_ReturnsLeafCert(t *testing.T) {
	signer := newOpenedSigner(t)

	cert := signer.Certificate()
	if cert == nil {
		t.Fatal("expected certificate, got nil")
	}

	wantCN := "signer-engine-test-leaf"
	if cert.Subject.CommonName != wantCN {
		t.Errorf("expected common name %q, got %q", wantCN, cert.Subject.CommonName)
	}
}

func TestSigner_Chain_ReturnsIntermediates(t *testing.T) {
	signer := newOpenedSigner(t)

	if len(signer.Chain()) == 0 {
		t.Fatal("expected certificates in the chain, got none")
	}
}

func TestSigner_Chain_LeafSignedByIntermediate(t *testing.T) {
	signer := newOpenedSigner(t)

	if err := signer.Certificate().CheckSignatureFrom(signer.Chain()[0]); err != nil {
		t.Fatalf("expected leaf to be signed by intermediate, got %v", err)
	}
}

func TestSigner_Chain_LeafIssuerMatchesIntermediateSubject(t *testing.T) {
	signer := newOpenedSigner(t)

	leafIssuer := signer.Certificate().Issuer.CommonName
	intermediateSubject := signer.Chain()[0].Subject.CommonName
	if leafIssuer != intermediateSubject {
		t.Fatalf("expected leaf issuer %q to match intermediate subject %q", leafIssuer, intermediateSubject)
	}
}

func TestSigner_Sign_ProducesVerifiableSignature(t *testing.T) {
	signer := newOpenedSigner(t)

	message := []byte("Hello, world!")
	hash := sha256.Sum256(message)

	signature, err := signer.Sign(hash[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	publicKey, ok := signer.Certificate().PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", signer.Certificate().PublicKey)
	}

	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature); err != nil {
		t.Fatalf("VerifyPKCS1v15 failed: %v", err)
	}
}
