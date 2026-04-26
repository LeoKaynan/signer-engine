package pkcs12_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"os"
	"signer-engine/internal/signer"
	"signer-engine/internal/signer/pkcs12"
	"testing"
)

const (
	path     = "../../../testdata/with_chain.p12"
	password = "test"
)

func newTestCredential(t *testing.T) signer.Credential {
	t.Helper()

	credential, err := pkcs12.NewCredentialFromFile(path, password)
	if err != nil {
		t.Fatalf("NewCredentialFromFile failed: %v", err)
	}
	return credential
}

func TestNewCredentialFromFile_RequiresPath(t *testing.T) {
	_, err := pkcs12.NewCredentialFromFile("", password)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestNewCredentialFromFile_FileNotFound(t *testing.T) {
	_, err := pkcs12.NewCredentialFromFile("does-not-exist.p12", password)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestNewCredentialFromFile_WrongPassword(t *testing.T) {
	_, err := pkcs12.NewCredentialFromFile(path, "wrong")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestNewCredentialFromFile_Valid(t *testing.T) {
	if _, err := pkcs12.NewCredentialFromFile(path, password); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestNewCredentialFromBytes_Valid(t *testing.T) {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if _, err := pkcs12.NewCredentialFromBytes(data, password); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestCredential_Certificate_ReturnsLeafCert(t *testing.T) {
	credential := newTestCredential(t)

	cert := credential.Certificate()
	if cert == nil {
		t.Fatal("expected certificate, got nil")
	}

	wantCN := "signer-engine-test-leaf"
	if cert.Subject.CommonName != wantCN {
		t.Errorf("expected common name %q, got %q", wantCN, cert.Subject.CommonName)
	}
}

func TestCredential_Chain_ReturnsIntermediates(t *testing.T) {
	credential := newTestCredential(t)

	if len(credential.Chain()) == 0 {
		t.Fatal("expected certificates in the chain, got none")
	}
}

func TestCredential_Chain_LeafSignedByIntermediate(t *testing.T) {
	credential := newTestCredential(t)

	if err := credential.Certificate().CheckSignatureFrom(credential.Chain()[0]); err != nil {
		t.Fatalf("expected leaf to be signed by intermediate, got %v", err)
	}
}

func TestCredential_Chain_LeafIssuerMatchesIntermediateSubject(t *testing.T) {
	credential := newTestCredential(t)

	leafIssuer := credential.Certificate().Issuer.CommonName
	intermediateSubject := credential.Chain()[0].Subject.CommonName
	if leafIssuer != intermediateSubject {
		t.Fatalf("expected leaf issuer %q to match intermediate subject %q", leafIssuer, intermediateSubject)
	}
}

func TestCredential_Sign_ProducesVerifiableSignature(t *testing.T) {
	credential := newTestCredential(t)

	message := []byte("Hello, world!")
	hash := sha256.Sum256(message)

	signature, err := credential.Sign(hash[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	publicKey, ok := credential.Certificate().PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", credential.Certificate().PublicKey)
	}

	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature); err != nil {
		t.Fatalf("VerifyPKCS1v15 failed: %v", err)
	}
}
