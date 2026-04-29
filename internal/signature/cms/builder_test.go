package cms

import (
	"crypto"
	"os"
	"os/exec"
	"path/filepath"
	"signer-engine/internal/testutil/certfixture"
	"testing"
)

func TestBuilder_Build(t *testing.T) {
	credential := certfixture.NewCredential(t)

	builder := Builder{
		Credential: credential,
		HashAlg:    crypto.SHA256,
		Detached:   false,
	}

	content := []byte("Hello, world!")

	sigDER, err := builder.Build(content)
	if err != nil {
		t.Fatalf("Build signature failed: %v", err)
	}

	tmp := t.TempDir()
	sigPath := filepath.Join(tmp, "signature.p7s")
	dataPath := filepath.Join(tmp, "data.bin")

	if err := os.WriteFile(sigPath, sigDER, 0o644); err != nil {
		t.Fatalf("failed to write signature file: %v", err)
	}
	if err := os.WriteFile(dataPath, content, 0o644); err != nil {
		t.Fatalf("failed to write data file: %v", err)
	}

	cmd := exec.Command("openssl", "cms", "-verify", "-noverify",
		"-inform", "DER",
		"-in", sigPath,
		"-content", dataPath,
		"-out", os.DevNull,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to verify signature: %v, output: %s", err, string(output))
	}
}
