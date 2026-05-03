package act

import (
	"context"
	"crypto"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSerproClient_Stamp(t *testing.T) {
	tokenDER := fakeContentInfo(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if r.Method != http.MethodPost {
				t.Fatalf("unexpected token method: %s", r.Method)
			}
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
			if r.Method != http.MethodPost {
				t.Fatalf("unexpected stamp method: %s", r.Method)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer access-token" {
				t.Fatalf("unexpected authorization header: %s", got)
			}
			if got := r.Header.Get("Content-Type"); got != timestampQueryContentType {
				t.Fatalf("unexpected content-type: %s", got)
			}
			var req timeStampRequest
			if _, err := readASN1Request(r, &req); err != nil {
				t.Fatalf("invalid timestamp request: %v", err)
			}
			w.Header().Set("Content-Type", "application/timestamp-token")
			_, _ = w.Write(tokenDER)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewSerproClient(SerproConfig{
		TokenURL:     server.URL + "/token",
		StampURL:     server.URL + "/stamp",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		HTTPClient:   server.Client(),
	})

	token, err := client.Stamp(context.Background(), []byte("signature-value"), crypto.SHA256)
	if err != nil {
		t.Fatalf("Stamp failed: %v", err)
	}
	if string(token.TokenDER) != string(tokenDER) {
		t.Fatal("unexpected token DER")
	}
}

func TestDecodeTimestampResponse_JSON(t *testing.T) {
	tokenDER := fakeContentInfo(t)
	body, err := json.Marshal(map[string]string{
		"timestampToken": base64.StdEncoding.EncodeToString(tokenDER),
	})
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}

	got, err := decodeTimestampResponse(body, "application/json")
	if err != nil {
		t.Fatalf("decodeTimestampResponse failed: %v", err)
	}
	if string(got) != string(tokenDER) {
		t.Fatal("unexpected token DER")
	}
}

func readASN1Request(r *http.Request, out any) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	_, err = asn1.Unmarshal(body, out)
	return body, err
}
