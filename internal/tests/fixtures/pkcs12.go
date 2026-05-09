package fixtures

import (
	"testing"

	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

const DefaultPKCS12Password = "test-password"

func NewPKCS12(t testing.TB, chain Chain, password string) []byte {
	t.Helper()

	chain.Validate(t)

	data, err := gopkcs12.Modern.Encode(
		chain.LeafKey,
		chain.Leaf,
		chain.Intermediates(),
		password,
	)
	if err != nil {
		t.Fatalf("failed to encode PKCS#12 fixture: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("PKCS#12 fixture is empty")
	}

	return data
}
