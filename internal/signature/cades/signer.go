package cades

import (
	"crypto"
	"fmt"
	"signer-engine/internal/keystore"
	"signer-engine/internal/signature/cms"
	"time"
)

type Signer struct {
	Signer   keystore.Signer
	HashAlg  crypto.Hash
	Detached bool
	Policy   cms.Policy
	Now      func() time.Time
}

func (s *Signer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

func (s *Signer) Sign(data []byte) ([]byte, error) {
	certificate := s.Signer.Certificate()

	if s.HashAlg == 0 {
		return nil, fmt.Errorf("hash algorithm is required")
	}

	if s.Policy != nil {
		if err := s.Policy.ValidateSigningCertificate(certificate); err != nil {
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
		Signer:                s.Signer,
		HashAlg:               s.HashAlg,
		Detached:              s.Detached,
		ExtraSignedAttributes: extras,
	}

	return builder.Build(data)
}
