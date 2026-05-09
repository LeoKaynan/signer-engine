package utils

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"signer-engine/internal/app/signing"
)

type OpenSSLTrustStore struct {
	RootsPEM         []byte
	IntermediatesPEM []byte
}

func VerifyAttachedCAdESWithOpenSSL(t testing.TB, signature []byte, trust ...OpenSSLTrustStore) {
	t.Helper()

	verifyCAdESWithOpenSSL(t, signature, nil, trust...)
}

func VerifyDetachedCAdESWithOpenSSL(t testing.TB, signature []byte, content []byte, trust ...OpenSSLTrustStore) {
	t.Helper()

	verifyCAdESWithOpenSSL(t, signature, content, trust...)
}

func VerifyCAdESWithOpenSSL(t testing.TB, signature []byte, content []byte, mode signing.Mode, trust ...OpenSSLTrustStore) {
	t.Helper()

	switch mode {
	case signing.ModeAttached:
		VerifyAttachedCAdESWithOpenSSL(t, signature, trust...)
	case signing.ModeDetached:
		VerifyDetachedCAdESWithOpenSSL(t, signature, content, trust...)
	default:
		t.Fatalf("unsupported CAdES mode: %s", mode)
	}
}

func verifyCAdESWithOpenSSL(t testing.TB, signature []byte, content []byte, trust ...OpenSSLTrustStore) {
	t.Helper()

	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skipf("openssl is not available: %v", err)
	}

	dir := t.TempDir()
	sigPath := filepath.Join(dir, "signature.p7s")
	if err := os.WriteFile(sigPath, signature, 0o600); err != nil {
		t.Fatalf("failed to write signature: %v", err)
	}

	args := []string{
		"openssl", "cms", "-verify",
		"-binary",
		"-inform", "DER",
		"-in", sigPath,
		"-out", os.DevNull,
	}
	if len(trust) == 0 {
		args = append(args, "-noverify")
	} else {
		store := trust[0]
		if len(store.RootsPEM) == 0 {
			t.Fatal("OpenSSL trust store roots PEM is empty")
		}
		rootsPath := filepath.Join(dir, "roots.pem")
		if err := os.WriteFile(rootsPath, store.RootsPEM, 0o600); err != nil {
			t.Fatalf("failed to write OpenSSL roots: %v", err)
		}
		args = append(args, "-CAfile", rootsPath)

		if len(store.IntermediatesPEM) != 0 {
			intermediatesPath := filepath.Join(dir, "intermediates.pem")
			if err := os.WriteFile(intermediatesPath, store.IntermediatesPEM, 0o600); err != nil {
				t.Fatalf("failed to write OpenSSL intermediates: %v", err)
			}
			args = append(args, "-certfile", intermediatesPath)
		}
	}
	if content != nil {
		contentPath := filepath.Join(dir, "content.bin")
		if err := os.WriteFile(contentPath, content, 0o600); err != nil {
			t.Fatalf("failed to write detached content: %v", err)
		}
		args = append(args, "-content", contentPath)
	}

	cmd := exec.Command(args[0], args[1:]...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl cms -verify failed: %v\noutput: %s", err, out)
	}
}
