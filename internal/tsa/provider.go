package tsa

import (
	"context"
	"crypto"
)

// Provider requests RFC 3161 timestamp tokens from an Autoridade de Carimbo do
// Tempo (ACT). The input is the data that must be hashed by the timestamp
// request, for CAdES AD-RT this is the CMS signature value.
type Provider interface {
	Stamp(ctx context.Context, input []byte, hashAlg crypto.Hash) (*TimestampToken, error)
}

type TimestampToken struct {
	TokenDER []byte
}
