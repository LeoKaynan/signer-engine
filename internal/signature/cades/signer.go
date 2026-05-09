package cades

import (
	"crypto"
	"fmt"
	"log/slog"
	"signer-engine/internal/signature/cms"
	"signer-engine/internal/signer"
	"signer-engine/internal/tsa"
	"signer-engine/internal/validation"
	"time"
)

type Signer struct {
	Credential             signer.Credential
	HashAlg                crypto.Hash
	Detached               bool
	Policy                 Policy
	TimeStampProvider      tsa.Provider
	TrustMaterialExtractor validation.TrustMaterialExtractor
	Now                    func() time.Time
}

func (s *Signer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

func (s *Signer) Sign(data []byte) ([]byte, error) {
	certificate := s.Credential.Certificate()
	slog.Info("cades: starting signer",
		"hash", s.HashAlg.String(),
		"detached", s.Detached,
		"data_bytes", len(data),
	)

	if s.HashAlg == 0 {
		return nil, fmt.Errorf("hash algorithm is required")
	}

	signingTime, err := SigningTimeAttribute(s.now())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signing time: %w", err)
	}
	slog.Info("cades: signing time attribute built")

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
		slog.Info("cades: validating signing certificate", "policy_oid", s.Policy.Identifier())
		if err := s.Policy.ValidateSigningCertificate(certificate, chain); err != nil {
			return nil, fmt.Errorf("failed to validate signing certificate: %w", err)
		}
		slog.Info("cades: signing certificate validated")

		if mand := s.Policy.MandatedHashAlg(); mand != 0 && mand != s.HashAlg {
			return nil, fmt.Errorf("hash algorithm does not match the mandated hash algorithm")
		}
		slog.Info("cades: mandated hash checked")

		policyAttrs, err := s.Policy.SignedAttributes(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to build policy signed attributes: %w", err)
		}
		slog.Info("cades: policy signed attributes built", "count", len(policyAttrs))

		extras = append(extras, policyAttrs...)
	} else {
		slog.Info("cades: no signature policy configured")
	}

	builder := cms.Builder{
		Credential:               s.Credential,
		HashAlg:                  s.HashAlg,
		Detached:                 s.Detached,
		ExtraSignedAttributes:    extras,
		UnsignedAttributeBuilder: s.unsignedAttributeBuilder(),
	}

	signature, err := builder.Build(data)
	if err != nil {
		return nil, err
	}
	slog.Info("cades: CMS build completed", "bytes", len(signature))

	return signature, nil
}
