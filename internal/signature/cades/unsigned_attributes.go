package cades

import (
	"context"
	"encoding/asn1"
	"fmt"
	"log/slog"

	"signer-engine/internal/signature/cms"
	"signer-engine/internal/signature/signaturepolicy"
	"signer-engine/internal/validation"
)

func (s *Signer) unsignedAttributeBuilder() cms.UnsignedAttributeBuilder {
	if s.Policy == nil || s.Policy.Level() < signaturepolicy.LevelT {
		slog.Info("cades: no unsigned attributes required")
		return nil
	}
	level := s.Policy.Level()
	slog.Info("cades: unsigned attributes required", "level", level)

	return func(ctx cms.UnsignedAttributeContext) ([]cms.Attribute, error) {
		var resolver *validation.SignatureTrustResolver
		if level >= signaturepolicy.LevelV {
			if s.TrustMaterialExtractor == nil {
				return nil, fmt.Errorf("trust material extractor is required")
			}
			resolver = validation.NewSignatureTrustResolver(s.TrustMaterialExtractor)
			if err := resolver.SetSigner(s.Credential.Certificate(), s.Credential.Chain()); err != nil {
				return nil, err
			}
		}

		builder := unsignedAttributeBuild{
			signer:   s,
			resolver: resolver,
			ctx:      ctx,
			level:    level,
		}
		return builder.build()
	}
}

type unsignedAttributeBuild struct {
	signer   *Signer
	resolver *validation.SignatureTrustResolver
	ctx      cms.UnsignedAttributeContext
	level    signaturepolicy.Level
}

func (b *unsignedAttributeBuild) build() ([]cms.Attribute, error) {
	var attrs []cms.Attribute

	// LevelT+: signature timestamp
	attr, err := b.signatureTimeStampToken()
	if err != nil {
		return nil, err
	}
	attrs = append(attrs, attr)

	if b.level < signaturepolicy.LevelV {
		return attrs, nil
	}

	// LevelV+: certificate refs, revocation refs, esc timestamp
	certRefs, err := b.certificateRefs()
	if err != nil {
		return nil, err
	}
	attrs = append(attrs, certRefs)

	revRefs, err := b.revocationRefs()
	if err != nil {
		return nil, err
	}
	attrs = append(attrs, revRefs)

	escTS, err := b.escTimeStamp(attrs)
	if err != nil {
		return nil, err
	}
	attrs = append(attrs, escTS)

	if b.level < signaturepolicy.LevelC {
		return attrs, nil
	}

	// LevelC+: certificate values, revocation values
	certVals, err := b.certValues()
	if err != nil {
		return nil, err
	}
	attrs = append(attrs, certVals)

	revVals, err := b.revocationValues()
	if err != nil {
		return nil, err
	}
	attrs = append(attrs, revVals)

	if b.level < signaturepolicy.LevelA {
		return attrs, nil
	}

	// LevelA: archive timestamp v2
	atsv2, err := b.archiveTimeStampV2(attrs)
	if err != nil {
		return nil, err
	}
	attrs = append(attrs, atsv2)

	return attrs, nil
}

func (b *unsignedAttributeBuild) signatureTimeStampToken() (cms.Attribute, error) {
	if b.signer.TimeStampProvider == nil {
		return cms.Attribute{}, fmt.Errorf("time stamp provider is required")
	}

	return b.stampAndWrap(
		context.Background(),
		b.ctx.Signature,
		"signature timestamp",
		cms.IdSignatureTimeStampToken,
	)
}

func (b *unsignedAttributeBuild) signerMaterial() (*validation.TrustMaterial, error) {
	if b.resolver == nil {
		return nil, fmt.Errorf("trust material extractor is required")
	}
	material, err := b.resolver.SignerMaterial(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to resolve signer trust material: %w", err)
	}
	return material, nil
}

func (b *unsignedAttributeBuild) certificateRefs() (cms.Attribute, error) {
	material, err := b.signerMaterial()
	if err != nil {
		return cms.Attribute{}, err
	}
	refsDER, err := BuildCertificateRefs(material.Chain)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to build certificate refs: %w", err)
	}
	return cms.RawAttribute(IdCertificateRefs, refsDER), nil
}

func (b *unsignedAttributeBuild) revocationRefs() (cms.Attribute, error) {
	material, err := b.signerMaterial()
	if err != nil {
		return cms.Attribute{}, err
	}
	refsDER, err := BuildRevocationRefs(material.CRLs)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to build revocation refs: %w", err)
	}
	return cms.RawAttribute(IdRevocationRefs, refsDER), nil
}

func (b *unsignedAttributeBuild) certValues() (cms.Attribute, error) {
	material, err := b.signerMaterial()
	if err != nil {
		return cms.Attribute{}, err
	}
	valuesDER, err := BuildCertificateValues(material.Chain)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to build cert values: %w", err)
	}
	return cms.RawAttribute(IdCertValues, valuesDER), nil
}

func (b *unsignedAttributeBuild) revocationValues() (cms.Attribute, error) {
	material, err := b.signerMaterial()
	if err != nil {
		return cms.Attribute{}, err
	}
	valuesDER, err := BuildRevocationValues(material.CRLs)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to build revocation values: %w", err)
	}
	return cms.RawAttribute(IdRevocationValues, valuesDER), nil
}

func (b *unsignedAttributeBuild) escTimeStamp(previousAttrs []cms.Attribute) (cms.Attribute, error) {
	if b.signer.TimeStampProvider == nil {
		return cms.Attribute{}, fmt.Errorf("time stamp provider is required")
	}

	slog.Info("cades: building esc timestamp input", "previous_unsigned_attrs", len(previousAttrs))
	input, err := EscTimeStampInput(b.ctx.Signature, previousAttrs)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to build esc timestamp input: %w", err)
	}

	return b.stampAndWrap(
		context.Background(),
		input,
		"esc timestamp",
		IdEscTimeStamp,
	)
}

func (b *unsignedAttributeBuild) archiveTimeStampV2(previousAttrs []cms.Attribute) (cms.Attribute, error) {
	if b.signer.TimeStampProvider == nil {
		return cms.Attribute{}, fmt.Errorf("time stamp provider is required")
	}

	slog.Info("cades: building archive timestamp input", "previous_unsigned_attrs", len(previousAttrs))
	input, err := ArchiveTimeStampV2Input(b.ctx, previousAttrs)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to build archive timestamp input: %w", err)
	}

	return b.stampAndWrap(
		context.Background(),
		input,
		"archive timestamp v2",
		IdArchiveTimeStampV2,
	)
}

func (b *unsignedAttributeBuild) stampAndWrap(
	ctx context.Context,
	input []byte,
	name string,
	id asn1.ObjectIdentifier,
) (cms.Attribute, error) {
	slog.Info("cades: requesting timestamp", "name", name, "input_bytes", len(input))
	token, err := b.signer.TimeStampProvider.Stamp(
		ctx,
		input,
		b.ctx.HashAlg,
	)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to stamp %s: %w", name, err)
	}
	slog.Info("cades: timestamp received", "name", name, "bytes", len(token.TokenDER))

	tokenDER, err := b.enrichTimestampToken(ctx, token.TokenDER)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to enrich %s token: %w", name, err)
	}

	return cms.RawAttribute(id, tokenDER), nil
}

func (b *unsignedAttributeBuild) enrichTimestampToken(ctx context.Context, tokenDER []byte) ([]byte, error) {
	if b.resolver == nil || b.level < signaturepolicy.LevelV {
		slog.Info("cades: timestamp token enrichment not required")
		return tokenDER, nil
	}
	return applyTokenEnrichment(ctx, tokenDER, b.resolver, b.level >= signaturepolicy.LevelC)
}

// applyTokenEnrichment adds TSA chain certificate/revocation references (and
// optionally values) as unsigned attributes inside the timestamp token's
// SignerInfo. The TSA signature remains valid because these are unsigned attrs.
//
// RFC 5126 §6.2.1/§6.2.2 — TSU certificate and revocation references shall be
// placed in the unsignedAttrs of the relevant timestamp token's SignerInfo.
func applyTokenEnrichment(ctx context.Context, tokenDER []byte, resolver *validation.SignatureTrustResolver, withValues bool) ([]byte, error) {
	material, err := resolver.AddTimestampToken(ctx, tokenDER)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve timestamp trust material: %w", err)
	}
	if material == nil {
		return tokenDER, nil
	}

	certRefsDER, err := BuildCertificateRefs(material.Chain)
	if err != nil {
		return nil, fmt.Errorf("failed to build timestamp certificate refs: %w", err)
	}
	revocationRefsDER, err := BuildRevocationRefs(material.CRLs)
	if err != nil {
		return nil, fmt.Errorf("failed to build timestamp revocation refs: %w", err)
	}

	var certValuesDER, revocationValuesDER []byte
	if withValues {
		certValuesDER, err = BuildCertificateValues(material.Chain)
		if err != nil {
			return nil, fmt.Errorf("failed to build timestamp cert values: %w", err)
		}
		revocationValuesDER, err = BuildRevocationValues(material.CRLs)
		if err != nil {
			return nil, fmt.Errorf("failed to build timestamp revocation values: %w", err)
		}
	}

	enriched, err := EnrichTimestampTokenWithRefs(tokenDER, certRefsDER, revocationRefsDER, certValuesDER, revocationValuesDER)
	if err != nil {
		return nil, err
	}
	slog.Info("cades: timestamp token enriched",
		"certificate_refs", len(certRefsDER),
		"revocation_refs", len(revocationRefsDER),
		"certificate_values", len(certValuesDER),
		"revocation_values", len(revocationValuesDER),
	)
	return enriched, nil
}
