package cms

import (
	"crypto"
	"os"
	"os/exec"
	"path/filepath"
	"signer-engine/internal/keystore/pkcs12"
	"testing"
)

func TestBuilder_Build(t *testing.T) {
	store := pkcs12.NewStore(pkcs12.Config{
		Path:     "../../../testdata/with_chain.p12",
		Password: "test",
	})

	if err := store.Open(); err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	signer, err := store.GetSigner()
	if err != nil {
		t.Fatalf("GetSigner failed: %v", err)
	}

	builder := Builder{
		Signer:   signer,
		HashAlg:  crypto.SHA256,
		Detached: false,
	}

	content := []byte("Hello, world!")

	sigDER, err := builder.Build(content)
	if err != nil {
		t.Fatalf("Build signature failed: %v", err)
	}

	tmp := t.TempDir()
	sigPath := filepath.Join(tmp, "signature.p7s")
	dataPath := filepath.Join(tmp, "data.bin")

	if err := os.WriteFile(sigPath, sigDER, 0644); err != nil {
		t.Fatalf("Failed to write signature file: %v", err)
	}
	if err := os.WriteFile(dataPath, content, 0644); err != nil {
		t.Fatalf("Failed to write data file: %v", err)
	}

	cmd := exec.Command("openssl", "cms", "-verify", "-noverify",
		"-inform", "DER",
		"-in", sigPath,
		"-content", dataPath,
		"-out", os.DevNull,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to verify signature: %v, output: %s", err, string(output))
	}
}
