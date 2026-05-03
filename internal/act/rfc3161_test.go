package act

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/asn1"
	"strings"
	"testing"

	"signer-engine/internal/cryptoutil"
)

func TestBuildRequest(t *testing.T) {
	input := []byte("signature-value")

	der, err := BuildRequest(input, crypto.SHA256)
	if err != nil {
		t.Fatalf("BuildRequest failed: %v", err)
	}

	var req timeStampRequest
	if _, err := asn1.Unmarshal(der, &req); err != nil {
		t.Fatalf("unmarshal TimeStampReq: %v", err)
	}

	if req.Version != 1 {
		t.Fatalf("unexpected version: %d", req.Version)
	}
	if !req.MessageImprint.HashAlgorithm.Algorithm.Equal(cryptoutil.OIDSHA256) {
		t.Fatalf("unexpected hash algorithm: %v", req.MessageImprint.HashAlgorithm.Algorithm)
	}

	expectedHash := sha256.Sum256(input)
	if !bytes.Equal(req.MessageImprint.HashedMessage, expectedHash[:]) {
		t.Fatal("unexpected message imprint hash")
	}
	if !req.CertReq {
		t.Fatal("expected certReq to be true")
	}
}

func TestExtractToken_RawContentInfo(t *testing.T) {
	tokenDER := fakeContentInfo(t)

	got, err := ExtractToken(tokenDER)
	if err != nil {
		t.Fatalf("ExtractToken failed: %v", err)
	}
	if !bytes.Equal(got, tokenDER) {
		t.Fatal("expected raw ContentInfo to be returned unchanged")
	}
}

func TestExtractToken_TimeStampResponse(t *testing.T) {
	tokenDER := fakeContentInfo(t)
	respDER, err := asn1.Marshal(struct {
		Status pkiStatusInfo
		Token  asn1.RawValue
	}{
		Status: pkiStatusInfo{Status: pkiStatusGranted},
		Token:  asn1.RawValue{FullBytes: tokenDER},
	})
	if err != nil {
		t.Fatalf("marshal TimeStampResp: %v", err)
	}

	got, err := ExtractToken(respDER)
	if err != nil {
		t.Fatalf("ExtractToken failed: %v", err)
	}
	if !bytes.Equal(got, tokenDER) {
		t.Fatal("expected embedded token to be returned")
	}
}

func TestExtractToken_RejectedTimeStampResponse(t *testing.T) {
	respDER, err := asn1.Marshal(struct {
		Status pkiStatusInfo
	}{
		Status: pkiStatusInfo{
			Status:       pkiStatusRejection,
			StatusString: []string{"bad request"},
			FailInfo: asn1.BitString{
				Bytes:     []byte{0x80},
				BitLength: 1,
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal TimeStampResp: %v", err)
	}

	_, err = ExtractToken(respDER)
	if err == nil {
		t.Fatal("expected rejected timestamp response to fail")
	}
	if !strings.Contains(err.Error(), "status=rejection") {
		t.Fatalf("expected rejection status in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "bad request") {
		t.Fatalf("expected status string in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "failInfo=80") {
		t.Fatalf("expected failInfo in error, got: %v", err)
	}
}

func TestExtractToken_GrantedResponseWithoutToken(t *testing.T) {
	respDER, err := asn1.Marshal(struct {
		Status pkiStatusInfo
	}{
		Status: pkiStatusInfo{Status: pkiStatusGranted},
	})
	if err != nil {
		t.Fatalf("marshal TimeStampResp: %v", err)
	}

	_, err = ExtractToken(respDER)
	if err == nil {
		t.Fatal("expected missing token to fail")
	}
	if !strings.Contains(err.Error(), "does not contain a token") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func fakeContentInfo(t *testing.T) []byte {
	t.Helper()

	der, err := asn1.Marshal(struct {
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
		t.Fatalf("marshal ContentInfo: %v", err)
	}
	return der
}
