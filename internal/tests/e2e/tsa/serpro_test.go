package tsa_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"signer-engine/internal/cryptoutil"
	"signer-engine/internal/signature/cms"
	"signer-engine/internal/tests/utils"
	"signer-engine/internal/tsa"
)

type timestampRequest struct {
	Version        int
	MessageImprint struct {
		HashAlgorithm cms.AlgorithmIdentifier
		HashedMessage []byte
	}
	CertReq bool `asn1:"optional"`
}

type timestampStatus struct {
	Status       int
	StatusString []string       `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

func TestSerproTimestampClientE2E(t *testing.T) {
	tokenDER := fakeTimestampToken(t)
	var tokenCalls int
	var stampCalls int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenCalls++
			username, password, ok := r.BasicAuth()
			if !ok || username != "client-id" || password != "client-secret" {
				t.Fatal("unexpected token credentials")
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "access-token",
				"expires_in":   300,
			})
		case "/stamp":
			stampCalls++
			if got := r.Header.Get("Authorization"); got != "Bearer access-token" {
				t.Fatalf("unexpected authorization header: %s", got)
			}
			if got := r.Header.Get("Content-Type"); got != "application/timestamp-query" {
				t.Fatalf("unexpected timestamp content type: %s", got)
			}
			assertTimestampRequest(t, r, []byte("signature-value"))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"timestampToken": base64.StdEncoding.EncodeToString(tokenDER),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := tsa.NewSerproClient(tsa.SerproConfig{
		TokenURL:     server.URL + "/token",
		StampURL:     server.URL + "/stamp",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		HTTPClient:   server.Client(),
	})

	for range 2 {
		token, err := client.Stamp(context.Background(), []byte("signature-value"), crypto.SHA256)
		if err != nil {
			t.Fatalf("Stamp failed: %v", err)
		}
		if !bytes.Equal(token.TokenDER, tokenDER) {
			t.Fatal("unexpected timestamp token DER")
		}
	}
	if tokenCalls != 1 {
		t.Fatalf("expected one OAuth token request due to cache, got %d", tokenCalls)
	}
	if stampCalls != 2 {
		t.Fatalf("expected two timestamp requests, got %d", stampCalls)
	}
}

func TestSerproTimestampClientRejectsDeniedTimestampResponse(t *testing.T) {
	responseDER, err := asn1.Marshal(struct {
		Status timestampStatus
	}{
		Status: timestampStatus{
			Status:       2,
			StatusString: []string{"bad request"},
			FailInfo: asn1.BitString{
				Bytes:     []byte{0x80},
				BitLength: 1,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to marshal rejected timestamp response: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-token"})
		case "/stamp":
			w.Header().Set("Content-Type", "application/timestamp-reply")
			_, _ = w.Write(responseDER)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := tsa.NewSerproClient(tsa.SerproConfig{
		TokenURL:     server.URL + "/token",
		StampURL:     server.URL + "/stamp",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		HTTPClient:   server.Client(),
	})

	_, err = client.Stamp(context.Background(), []byte("signature-value"), crypto.SHA256)
	utils.RequireErrorContains(t, err, "status=rejection")
	utils.RequireErrorContains(t, err, "bad request")
	utils.RequireErrorContains(t, err, "failInfo=80")
}

func assertTimestampRequest(t testing.TB, r *http.Request, input []byte) {
	t.Helper()

	var request timestampRequest
	if _, err := asn1.Unmarshal(readBody(t, r), &request); err != nil {
		t.Fatalf("invalid timestamp request: %v", err)
	}
	if request.Version != 1 {
		t.Fatalf("unexpected timestamp request version: %d", request.Version)
	}
	if !request.MessageImprint.HashAlgorithm.Algorithm.Equal(cryptoutil.OIDSHA256) {
		t.Fatalf("unexpected timestamp hash OID: %s", request.MessageImprint.HashAlgorithm.Algorithm)
	}
	expectedHash := sha256.Sum256(input)
	if !bytes.Equal(request.MessageImprint.HashedMessage, expectedHash[:]) {
		t.Fatal("unexpected timestamp message imprint")
	}
	if !request.CertReq {
		t.Fatal("expected timestamp request certReq=true")
	}
}

func readBody(t testing.TB, r *http.Request) []byte {
	t.Helper()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r.Body); err != nil {
		t.Fatalf("failed to read request body: %v", err)
	}
	return buf.Bytes()
}

func fakeTimestampToken(t testing.TB) []byte {
	t.Helper()

	signedDataDER, err := asn1.Marshal(cms.SignedData{
		Version: 1,
		EncapContentInfo: cms.EncapsulatedContentInfo{
			EContentType: cms.OIDData,
		},
	})
	if err != nil {
		t.Fatalf("failed to marshal timestamp signed data: %v", err)
	}
	tokenDER, err := asn1.Marshal(cms.ContentInfo{
		ContentType: cms.OIDSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      signedDataDER,
		},
	})
	if err != nil {
		t.Fatalf("failed to marshal timestamp token: %v", err)
	}
	return tokenDER
}
