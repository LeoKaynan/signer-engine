package cades

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"signer-engine/internal/constants"
	"signer-engine/internal/keystore/pkcs12"
)

func TestSigner_Sign(t *testing.T) {
	store := pkcs12.NewStore(pkcs12.Config{
		Path:     "../../../testdata/with_chain.p12",
		Password: "test",
	})
	if err := store.Open(); err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	keySigner, err := store.GetSigner("")
	if err != nil {
		t.Fatalf("GetSigner failed: %v", err)
	}

	cadesSigner := Signer{
		Signer:   keySigner,
		HashAlg:  crypto.SHA256,
		Detached: false,
	}

	content := []byte("Hello, CAdES!")

	sigDER, err := cadesSigner.Sign(content)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	tmp := t.TempDir()
	sigPath := filepath.Join(tmp, "signature.p7s")
	dataPath := filepath.Join(tmp, "data.bin")

	if err := os.WriteFile(sigPath, sigDER, 0o644); err != nil {
		t.Fatalf("write sig: %v", err)
	}
	if err := os.WriteFile(dataPath, content, 0o644); err != nil {
		t.Fatalf("write data: %v", err)
	}

	cmd := exec.Command("openssl", "cms", "-verify", "-noverify",
		"-inform", "DER",
		"-in", sigPath,
		"-content", dataPath,
		"-out", os.DevNull,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl cms -verify failed: %v\noutput: %s", err, out)
	}

	signingTimeOIDDER, err := asn1.Marshal(constants.OIDSigningTime)
	if err != nil {
		t.Fatalf("marshal OID: %v", err)
	}
	if !bytes.Contains(sigDER, signingTimeOIDDER) {
		t.Error("signing-time OID not present in signature")
	}

	sigCertV2OIDDER, err := asn1.Marshal(constants.OIDSigningCertificateV2)
	if err != nil {
		t.Fatalf("marshal OID: %v", err)
	}
	if !bytes.Contains(sigDER, sigCertV2OIDDER) {
		t.Error("signing-certificate-v2 OID not present in signature")
	}
}
