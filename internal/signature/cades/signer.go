package cades

import (
	"crypto"
	"fmt"
	"signer-engine/internal/signature/cms"
	"signer-engine/internal/signer"
	"time"
)

type Signer struct {
	Credential signer.Credential
	HashAlg    crypto.Hash
	Detached   bool
	Policy     Policy
	Now        func() time.Time
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

	if s.Policy != nil {
		if err := s.Policy.ValidateSigningCertificate(certificate, s.Credential.Chain()); err != nil {
			return nil, fmt.Errorf("failed to validate signing certificate: %w", err)
		}
		if mand := s.Policy.MandatedHashAlg(); mand != 0 && mand != s.HashAlg {
			return nil, fmt.Errorf("hash algorithm does not match the mandated hash algorithm")
		}
	}

	signingTime, err := SigningTimeAttribute(s.now())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signing time: %w", err)
	}

	signingCertificateV2, err := SigningCertificateV2Attribute(certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signing certificate v2: %w", err)
	}

	extras := []cms.Attribute{
		signingTime,
		signingCertificateV2,
	}

	if s.Policy != nil {
		extras = append(extras, s.Policy.SignedAttributes()...)
	}

	builder := cms.Builder{
		Credential:            s.Credential,
		HashAlg:               s.HashAlg,
		Detached:              s.Detached,
		ExtraSignedAttributes: extras,
	}

	return builder.Build(data)
}
