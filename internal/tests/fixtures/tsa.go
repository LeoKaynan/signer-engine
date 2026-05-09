package fixtures

import (
	"context"
	"crypto"
	"encoding/asn1"
	"testing"

	"signer-engine/internal/cryptoutil"
	"signer-engine/internal/signature/cms"
	"signer-engine/internal/tsa"
)

type TimeStampProvider struct {
	t testing.TB

	Inputs   [][]byte
	HashAlgs []crypto.Hash
}

func NewTimeStampProvider(t testing.TB) *TimeStampProvider {
	t.Helper()

	return &TimeStampProvider{t: t}
}

func (p *TimeStampProvider) Stamp(ctx context.Context, input []byte, hashAlg crypto.Hash) (*tsa.TimestampToken, error) {
	p.t.Helper()

	p.Inputs = append(p.Inputs, append([]byte(nil), input...))
	p.HashAlgs = append(p.HashAlgs, hashAlg)

	tokenDER, err := timestampTokenDER()
	if err != nil {
		return nil, err
	}

	return &tsa.TimestampToken{TokenDER: tokenDER}, nil
}

func timestampTokenDER() ([]byte, error) {
	signedDataDER, err := asn1.Marshal(cms.SignedData{
		Version: 1,
		DigestAlgorithms: []cms.AlgorithmIdentifier{
			{
				Algorithm: cryptoutil.OIDSHA256,
			},
		},
		EncapContentInfo: cms.EncapsulatedContentInfo{
			EContentType: cms.OIDData,
		},
	})
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(cms.ContentInfo{
		ContentType: cms.OIDSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      signedDataDER,
		},
	})
}
