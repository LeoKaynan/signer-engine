package cades

import (
	"context"
	"crypto"
	"encoding/asn1"
	"fmt"
	"signer-engine/internal/signature/cms"
	"signer-engine/internal/signature/signaturepolicy"
	"signer-engine/internal/signer"
	"signer-engine/internal/tsa"
	"signer-engine/internal/validation"
)

type Signer struct {
	Credential             signer.Credential
	HashAlg                crypto.Hash
	Detached               bool
	Policy                 Policy
	TimeStampProvider      tsa.Provider
	TrustMaterialExtractor validation.TrustMaterialExtractor
	Clock                  signaturepolicy.Clock
}

// strippedATSv2Policy wraps a Policy and caps its Level at LevelC, excluding
// the ATSv2 step. Used during co-signing so the fresh co-signer is built
// without ATSv2; renewal is applied afterwards for every signer in the merged
// CMS (see CoSign and renewAllArchiveTimeStamps).
type strippedATSv2Policy struct{ Policy }

func (p strippedATSv2Policy) Level() signaturepolicy.Level {
	l := p.Policy.Level()
	if l > signaturepolicy.LevelC {
		return signaturepolicy.LevelC
	}
	return l
}

func (s *Signer) policyHasArchiveTimeStamp() bool {
	return s.Policy != nil && s.Policy.Level() >= signaturepolicy.LevelA
}

// Sign implements signaturepolicy.Signer. It transparently dispatches between
// fresh signing and co-signing based on the input:
//
//   - input.ExistingSignature non-empty → detached co-sign over input.Data.
//   - input.Data is itself a CMS SignedData and the signer is attached →
//     attached co-sign (the embedded content is the document).
//   - otherwise → fresh signature over input.Data.
func (s *Signer) Sign(input signaturepolicy.SignInput) ([]byte, error) {
	if len(input.ExistingSignature) > 0 {
		return s.coSign(input.ExistingSignature, input.Data)
	}
	if !s.Detached && IsAlreadySigned(input.Data) {
		return s.coSign(input.Data, nil)
	}
	return s.signFresh(input.Data)
}

// SignFresh produces a single-signer CMS over data. Exposed for callers that
// want explicit control; the unified Sign(SignInput) is the recommended entry.
func (s *Signer) SignFresh(data []byte) ([]byte, error) {
	return s.signFresh(data)
}

func (s *Signer) signFresh(data []byte) ([]byte, error) {
	builder, err := s.prepareBuilder()
	if err != nil {
		return nil, err
	}
	return builder.Build(data)
}

// coSign adds a parallel signature (co-assinatura) to existingSignature.
//
// RFC 5652 §5.1 allows SignedData.signerInfos to carry multiple SignerInfo
// entries; each signer independently signs the same content.
//
// When the policy is AD-RA (includes ArchiveTimeStampV2), co-signing requires
// special handling because the ATSv2 hash input covers SignedData.Certificates
// (RFC 5126 §6.4.1, bullet 3). Adding the co-signer's certificate chain to that
// field would break every existing ATSv2 token. The solution is:
//  1. Build the fresh co-signer without ATSv2 (using strippedATSv2Policy).
//  2. Merge the two CMS structures (Certificates now contains all chains).
//  3. Renew ATSv2 for every SignerInfo so the new token covers the merged set.
//
// Note: contra-assinaturas (countersignature attributes) are explicitly
// prohibited after ATSv2 by DOC-ICP-15.03 §Anexo 1, Tabela A.3, Nota.
func (s *Signer) coSign(existingSignature []byte, originalData []byte) ([]byte, error) {
	coSigner := *s
	if s.policyHasArchiveTimeStamp() {
		coSigner.Policy = strippedATSv2Policy{s.Policy}
	}

	builder, err := coSigner.prepareBuilder()
	if err != nil {
		return nil, err
	}

	merged, err := builder.CoSign(existingSignature, originalData)
	if err != nil {
		return nil, fmt.Errorf("cades: co-sign: %w", err)
	}

	if !s.policyHasArchiveTimeStamp() {
		return merged, nil
	}

	return s.renewAllArchiveTimeStamps(merged, originalData)
}

// renewAllArchiveTimeStamps replaces (or adds) ATSv2 in every SignerInfo of the
// merged CMS. Each renewal computes a fresh hash input via ArchiveTimeStampV2Input
// using the current (merged) Certificates field, so the new token seals the
// complete set of signers and certificates (RFC 5126 §6.4.1).
func (s *Signer) renewAllArchiveTimeStamps(mergedCMS []byte, originalContent []byte) ([]byte, error) {
	var contentInfo cms.ContentInfo
	if _, err := asn1.Unmarshal(mergedCMS, &contentInfo); err != nil {
		return nil, fmt.Errorf("failed to parse merged CMS: %w", err)
	}

	var signedData cms.SignedData
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signedData); err != nil {
		return nil, fmt.Errorf("failed to parse SignedData: %w", err)
	}

	if len(signedData.SignerInfos) == 0 {
		return nil, fmt.Errorf("cannot renew ATSv2: merged CMS has no signers")
	}

	detached := signedData.EncapContentInfo.EContent == nil
	if detached != s.Detached {
		return nil, fmt.Errorf("CMS detached mode (%v) does not match signer configuration (%v)", detached, s.Detached)
	}

	data := originalContent
	if !detached {
		data = signedData.EncapContentInfo.EContent
	}

	withValues := s.Policy.Level() >= signaturepolicy.LevelC

	for i := range signedData.SignerInfos {
		si := &signedData.SignerInfos[i]

		// Collect unsigned attrs without any existing ATSv2.
		var attrsWithoutATSv2 []cms.Attribute
		for _, attr := range si.UnsignedAttrs {
			if !attr.AttrType.Equal(IdArchiveTimeStampV2) {
				attrsWithoutATSv2 = append(attrsWithoutATSv2, attr)
			}
		}

		ctx := cms.UnsignedAttributeContext{
			EncapContentInfo: signedData.EncapContentInfo,
			Certificates:     signedData.Certificates,
			CRLs:             signedData.CRLs,
			SignerInfo:       *si,
			Detached:         detached,
			Data:             data,
			HashAlg:          s.HashAlg,
		}

		input, err := ArchiveTimeStampV2Input(ctx, attrsWithoutATSv2)
		if err != nil {
			return nil, fmt.Errorf("failed to compute ATSv2 renewal input for signer %d: %w", i, err)
		}

		token, err := s.TimeStampProvider.Stamp(context.Background(), input, s.HashAlg)
		if err != nil {
			return nil, fmt.Errorf("failed to request ATSv2 renewal token for signer %d: %w", i, err)
		}

		tokenDER := token.TokenDER
		if s.TrustMaterialExtractor != nil {
			tokenDER, err = s.enrichATSv2Token(tokenDER, withValues)
			if err != nil {
				return nil, fmt.Errorf("failed to enrich ATSv2 renewal token for signer %d: %w", i, err)
			}
		}

		si.UnsignedAttrs = append(attrsWithoutATSv2, cms.RawAttribute(IdArchiveTimeStampV2, tokenDER))
	}

	signedDataBytes, err := asn1.Marshal(signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal renewed SignedData: %w", err)
	}

	contentInfo.Content = asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      signedDataBytes,
	}

	return asn1.Marshal(contentInfo)
}

// enrichATSv2Token delegates to applyTokenEnrichment with a fresh resolver
// scoped to the TSA certificate that signed the token being enriched.
func (s *Signer) enrichATSv2Token(tokenDER []byte, withValues bool) ([]byte, error) {
	resolver := validation.NewSignatureTrustResolver(s.TrustMaterialExtractor)
	return applyTokenEnrichment(context.Background(), tokenDER, resolver, withValues)
}

func (s *Signer) prepareBuilder() (*cms.Builder, error) {
	if s.HashAlg == 0 {
		return nil, fmt.Errorf("cades: hash algorithm is required")
	}

	signingTime, err := cms.SigningTimeAttribute(s.Clock.Now())
	if err != nil {
		return nil, fmt.Errorf("cades: build signing time attribute: %w", err)
	}

	extras := []cms.Attribute{signingTime}

	ctx := SigningContext{
		Certificate: s.Credential.Certificate(),
		Chain:       s.Credential.Chain(),
		HashAlg:     s.HashAlg,
		Detached:    s.Detached,
	}

	if err := signaturepolicy.ValidatePolicyPrerequisites(s.Policy, s.HashAlg, ctx.Certificate, ctx.Chain); err != nil {
		return nil, fmt.Errorf("cades: %w", err)
	}

	if s.Policy != nil {
		policyAttrs, err := s.Policy.SignedAttributes(ctx)
		if err != nil {
			return nil, fmt.Errorf("cades: build policy signed attributes: %w", err)
		}
		extras = append(extras, policyAttrs...)
	}

	return &cms.Builder{
		Credential:               s.Credential,
		HashAlg:                  s.HashAlg,
		Detached:                 s.Detached,
		ExtraSignedAttributes:    extras,
		UnsignedAttributeBuilder: s.unsignedAttributeBuilder(),
	}, nil
}
