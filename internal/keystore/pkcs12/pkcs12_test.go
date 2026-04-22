package pkcs12_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"signer-engine/internal/keystore/pkcs12"
	"testing"
)

const (
	path     = "../../../testdata/with_chain.p12"
	password = "test"
)

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
	_, err := store.GetSigner("")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestStore_Open_Valid(t *testing.T) {
	store := pkcs12.NewStore(pkcs12.Config{
		Path:     path,
		Password: password,
	})
	err := store.Open()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestStore_GetSigner_Valid(t *testing.T) {
	store := pkcs12.NewStore(pkcs12.Config{
		Path:     path,
		Password: password,
	})
	err := store.Open()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	signer, err := store.GetSigner("")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if signer == nil {
		t.Fatal("expected signer, got nil")
	}

	cert := signer.Certificate()
	if cert == nil {
		t.Fatal("expected certificate, got nil")
	}
	wantCN := "signer-engine-test-leaf"
	if cert.Subject.CommonName != wantCN {
		t.Fatalf("expected certificate common name to be %q, got %q", wantCN, cert.Subject.CommonName)
	}
}

func TestStore_Chain_ReturnsIntermidates(t *testing.T) {
	store := pkcs12.NewStore(pkcs12.Config{
		Path:     path,
		Password: password,
	})
	err := store.Open()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer store.Close()

	signer, err := store.GetSigner("")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if signer == nil {
		t.Fatal("expected signer, got nil")
	}

	chain := signer.Chain()
	if len(chain) == 0 {
		t.Fatal("expected certificates in the chain, got none")
	}
}

func TestStore_Sign_ProducesVerifiableSignature(t *testing.T) {
	store := pkcs12.NewStore(pkcs12.Config{
		Path:     path,
		Password: password,
	})

	err := store.Open()
	if err != nil {
		t.Fatalf("Open() failed: %v", err)
	}
	defer store.Close()

	signer, err := store.GetSigner("")
	if err != nil {
		t.Fatalf("GetSigner() failed: %v", err)
	}

	message := []byte("Hello, world!")
	hash := sha256.Sum256(message)

	signature, err := signer.Sign(hash[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	publicKey, ok := signer.Certificate().PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("expected public key to be an RSA public key")
	}

	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature); err != nil {
		t.Fatalf("VerifyPKCS1v15() failed: %v", err)
	}
}
