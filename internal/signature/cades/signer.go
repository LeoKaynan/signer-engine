package cades

import (
	"context"
	"crypto"
	"fmt"
	"signer-engine/internal/tsa"
	"signer-engine/internal/signature/cms"
	"signer-engine/internal/signer"
	"time"
)

type Signer struct {
	Credential        signer.Credential
	HashAlg           crypto.Hash
	Detached          bool
	Policy            Policy
	TimeStampProvider tsa.Provider
	Now               func() time.Time
}

func (s *Signer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

func (s *Signer) Sign(data []byte) ([]byte, error) {
	certificate := s.Credential.Certificate()

	if s.HashAlg == 0 {
		return nil, fmt.Errorf("hash algorithm is required")
	}

	signingTime, err := SigningTimeAttribute(s.now())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signing time: %w", err)
	}

	extras := []cms.Attribute{
		signingTime,
	}

	chain := s.Credential.Chain()

	ctx := SigningContext{
		Certificate: certificate,
		Chain:       chain,
		HashAlg:     s.HashAlg,
		Detached:    s.Detached,
	}

	if s.Policy != nil {
		if err := s.Policy.ValidateSigningCertificate(certificate, chain); err != nil {
			return nil, fmt.Errorf("failed to validate signing certificate: %w", err)
		}
		if mand := s.Policy.MandatedHashAlg(); mand != 0 && mand != s.HashAlg {
			return nil, fmt.Errorf("hash algorithm does not match the mandated hash algorithm")
		}

		policyAttrs, err := s.Policy.SignedAttributes(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to build policy signed attributes: %w", err)
		}

		extras = append(extras, policyAttrs...)
	}

	builder := cms.Builder{
		Credential:               s.Credential,
		HashAlg:                  s.HashAlg,
		Detached:                 s.Detached,
		ExtraSignedAttributes:    extras,
		UnsignedAttributeBuilder: s.unsignedAttributeBuilder(),
	}

	return builder.Build(data)
}

func (s *Signer) unsignedAttributeBuilder() cms.UnsignedAttributeBuilder {
	if s.Policy == nil || len(s.Policy.UnsignedAttributeNames()) == 0 {
		return nil
	}

	return func(ctx cms.UnsignedAttributeContext) ([]cms.Attribute, error) {
		var attrs []cms.Attribute

		for _, name := range s.Policy.UnsignedAttributeNames() {
			switch name {
			case SignatureTimeStampTokenAttr:
				if s.TimeStampProvider == nil {
					return nil, fmt.Errorf("time stamp provider is required")
				}

				token, err := s.TimeStampProvider.Stamp(
					context.Background(),
					ctx.Signature,
					ctx.HashAlg,
				)
				if err != nil {
					return nil, fmt.Errorf("failed to stamp signature: %w", err)
				}

				attr, err := SignatureTimeStampTokenAttribute(token.TokenDER)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal signature time stamp token attribute: %w", err)
				}

				attrs = append(attrs, attr)

			default:
				return nil, fmt.Errorf("unsupported unsigned attribute: %s", name)
			}
		}

		return attrs, nil
	}

}
