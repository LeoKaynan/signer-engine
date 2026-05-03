package cades_test

import (
	"bytes"
	"context"
	"crypto"
	"encoding/asn1"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"signer-engine/internal/act"
	"signer-engine/internal/signature/cades"
	"signer-engine/internal/signature/cms"
	"signer-engine/internal/testutil/certfixture"
	"signer-engine/internal/testutil/policyfixture"
)

func TestSigner_Sign(t *testing.T) {
	credential := certfixture.NewCredential(t)

	cadesSigner := cades.Signer{
		Credential: credential,
		HashAlg:    crypto.SHA256,
		Detached:   false,
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

	signingTimeOIDDER, err := asn1.Marshal(cms.OIDSigningTime)
	if err != nil {
		t.Fatalf("marshal OID: %v", err)
	}
	if !bytes.Contains(sigDER, signingTimeOIDDER) {
		t.Error("signing-time OID not present in signature")
	}
}

type fakeTimeStampProvider struct {
	input   []byte
	hashAlg crypto.Hash
}

func (p *fakeTimeStampProvider) Stamp(ctx context.Context, input []byte, hashAlg crypto.Hash) (*act.TimestampToken, error) {
	p.input = append([]byte(nil), input...)
	p.hashAlg = hashAlg

	tokenDER, err := asn1.Marshal(struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}{
		ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		Content: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSequence,
			IsCompound: true,
			Bytes:      []byte{0x05, 0x00},
		},
	})
	if err != nil {
		return nil, err
	}

	return &act.TimestampToken{TokenDER: tokenDER}, nil
}

func TestSigner_SignWithSignatureTimeStamp(t *testing.T) {
	credential := certfixture.NewCredential(t)
	policy := policyfixture.Policy{
		UnsignedAttrs: []cades.AttributeName{
			cades.SignatureTimeStampTokenAttr,
		},
	}
	timeStampProvider := &fakeTimeStampProvider{}

	cadesSigner := cades.Signer{
		Credential:        credential,
		HashAlg:           crypto.SHA256,
		Detached:          false,
		Policy:            policy,
		TimeStampProvider: timeStampProvider,
	}

	sigDER, err := cadesSigner.Sign([]byte("Hello, CAdES AD-RT!"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(timeStampProvider.input) == 0 {
		t.Fatal("expected timestamp provider to receive signature bytes")
	}
	if timeStampProvider.hashAlg != crypto.SHA256 {
		t.Fatalf("unexpected timestamp hash alg: %v", timeStampProvider.hashAlg)
	}

	oidDER, err := asn1.Marshal(cades.OIDSignatureTimeStampToken)
	if err != nil {
		t.Fatalf("marshal OID: %v", err)
	}
	if !bytes.Contains(sigDER, oidDER) {
		t.Fatal("signature timestamp token OID not present in signature")
	}
}

func TestSigner_SignWithSignatureTimeStampRequiresProvider(t *testing.T) {
	credential := certfixture.NewCredential(t)
	policy := policyfixture.Policy{
		UnsignedAttrs: []cades.AttributeName{
			cades.SignatureTimeStampTokenAttr,
		},
	}

	cadesSigner := cades.Signer{
		Credential: credential,
		HashAlg:    crypto.SHA256,
		Detached:   false,
		Policy:     policy,
	}

	_, err := cadesSigner.Sign([]byte("Hello, CAdES AD-RT!"))
	if err == nil {
		t.Fatal("expected missing timestamp provider error")
	}
	if !strings.Contains(err.Error(), "time stamp provider is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}
