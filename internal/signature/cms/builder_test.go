package cms

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"errors"
	"fmt"
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

func TestBuilder_BuildWithUnsignedAttributes(t *testing.T) {
	credential := certfixture.NewCredential(t)
	unsignedAttrOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	unsignedAttrValueDER, err := asn1.Marshal([]byte("unsigned-value"))
	if err != nil {
		t.Fatalf("failed to marshal unsigned attribute value: %v", err)
	}

	var callbackCalled bool

	builder := Builder{
		Credential: credential,
		HashAlg:    crypto.SHA256,
		Detached:   false,
		UnsignedAttributeBuilder: func(ctx UnsignedAttributeContext) ([]Attribute, error) {
			callbackCalled = true

			if len(ctx.Signature) == 0 {
				return nil, errors.New("signature is empty")
			}

			if ctx.HashAlg != crypto.SHA256 {
				return nil, fmt.Errorf("hash algorithm is not SHA256")
			}

			return []Attribute{
				{
					AttrType: unsignedAttrOID,
					AttrValues: []asn1.RawValue{
						{FullBytes: unsignedAttrValueDER},
					},
				},
			}, nil
		},
	}

	sigDER, err := builder.Build([]byte("Hello, world!"))
	if err != nil {
		t.Fatalf("Build signature failed: %v", err)
	}

	if !callbackCalled {
		t.Error("expected unsigned attribute builder to be called")
	}

	unsignedAttrOIDDER, err := asn1.Marshal(unsignedAttrOID)
	if err != nil {
		t.Fatalf("failed to marshal unsigned attribute OID: %v", err)
	}

	if !bytes.Contains(sigDER, unsignedAttrOIDDER) {
		t.Fatal("unsigned attribute OID not present in signature")
	}
}
