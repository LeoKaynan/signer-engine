package pkcs12_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	pkcs12provider "signer-engine/internal/signer/pkcs12"
	"signer-engine/internal/tests/fixtures"
	"signer-engine/internal/tests/utils"
)

func TestPKCS12ProviderLoadsCredentialFromFile(t *testing.T) {
	chain := fixtures.NewChain(t)
	path := writePKCS12File(t, chain)

	credential, err := pkcs12provider.NewCredentialFromFile(path, fixtures.DefaultPKCS12Password)
	if err != nil {
		t.Fatalf("NewCredentialFromFile failed: %v", err)
	}
	if credential.Certificate() == nil {
		t.Fatal("expected leaf certificate")
	}
	if credential.Certificate().SerialNumber.Cmp(chain.Leaf.SerialNumber) != 0 {
		t.Fatalf("unexpected leaf serial: got=%s want=%s", credential.Certificate().SerialNumber, chain.Leaf.SerialNumber)
	}
	if len(credential.Chain()) != 1 {
		t.Fatalf("expected one intermediate certificate, got %d", len(credential.Chain()))
	}
	if err := credential.Certificate().CheckSignatureFrom(credential.Chain()[0]); err != nil {
		t.Fatalf("expected leaf to be signed by intermediate: %v", err)
	}

	digest := sha256.Sum256([]byte("signer-engine pkcs12 file e2e"))
	signature, err := credential.Sign(digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("credential Sign failed: %v", err)
	}
	publicKey, ok := credential.Certificate().PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected RSA public key, got %T", credential.Certificate().PublicKey)
	}
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

func TestPKCS12ProviderRejectsInvalidFileInput(t *testing.T) {
	chain := fixtures.NewChain(t)
	path := writePKCS12File(t, chain)

	tests := []struct {
		name       string
		path       string
		password   string
		wantErrSub string
	}{
		{
			name:       "empty path",
			path:       "",
			password:   fixtures.DefaultPKCS12Password,
			wantErrSub: "path is required",
		},
		{
			name:       "file not found",
			path:       filepath.Join(t.TempDir(), "missing.p12"),
			password:   fixtures.DefaultPKCS12Password,
			wantErrSub: "failed to read file",
		},
		{
			name:       "wrong password",
			path:       path,
			password:   "wrong-password",
			wantErrSub: "failed to decode chain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pkcs12provider.NewCredentialFromFile(tt.path, tt.password)
			utils.RequireErrorContains(t, err, tt.wantErrSub)
		})
	}
}

func writePKCS12File(t testing.TB, chain fixtures.Chain) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "credential.p12")
	if err := os.WriteFile(path, fixtures.NewPKCS12(t, chain, fixtures.DefaultPKCS12Password), 0o600); err != nil {
		t.Fatalf("failed to write PKCS#12 fixture: %v", err)
	}
	return path
}
