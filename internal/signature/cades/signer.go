package cades

import (
	"crypto"
	"fmt"
	"signer-engine/internal/signature/cms"
	"signer-engine/internal/signer"
	"signer-engine/internal/tsa"
	"signer-engine/internal/validation"
	"time"
)

type Signer struct {
	Credential         signer.Credential
	HashAlg            crypto.Hash
	Detached           bool
	Policy             Policy
	TimeStampProvider  tsa.Provider
	ValidationProvider validation.Provider
	Now                func() time.Time
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
