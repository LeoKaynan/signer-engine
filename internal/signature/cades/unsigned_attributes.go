package cades

import (
	"context"
	"fmt"
	"log/slog"

	"signer-engine/internal/signature/cms"
	"signer-engine/internal/validation"
)

func (s *Signer) unsignedAttributeBuilder() cms.UnsignedAttributeBuilder {
	if s.Policy == nil || len(s.Policy.UnsignedAttributeNames()) == 0 {
		slog.Info("cades: no unsigned attributes required")
		return nil
	}
	names := s.Policy.UnsignedAttributeNames()
	slog.Info("cades: unsigned attributes required", "count", len(names), "names", names)

	return func(ctx cms.UnsignedAttributeContext) ([]cms.Attribute, error) {
		var resolver *validation.SignatureTrustResolver
		if requiresValidationRefs(names) || requiresValidationValues(names) {
			if s.TrustMaterialExtractor == nil {
				return nil, fmt.Errorf("trust material extractor is required")
			}
			resolver = validation.NewSignatureTrustResolver(s.TrustMaterialExtractor)
			if err := resolver.SetSigner(s.Credential.Certificate(), s.Credential.Chain()); err != nil {
				return nil, err
			}
		}

		builder := unsignedAttributeBuild{
			signer:                s,
			resolver:              resolver,
			ctx:                   ctx,
			enrichTimestampTokens: requiresValidationRefs(names),
			enrichTimestampValues: requiresValidationValues(names),
		}
		return builder.build(names)
	}
}

func requiresValidationRefs(names []AttributeName) bool {
	// RFC 5126 6.2.1/6.2.2 allows TSU validation refs to be carried
	// inside the relevant timestamp token as unsignedAttrs.
	// https://www.rfc-editor.org/rfc/rfc5126#section-6.2.1
	for _, name := range names {
		if name == CertificateRefsAttr || name == RevocationRefsAttr || name == EscTimeStampAttr {
			return true
		}
	}
	return false
}

func requiresValidationValues(names []AttributeName) bool {
	for _, name := range names {
		if name == CertValuesAttr || name == RevocationValuesAttr {
			return true
		}
	}
	return false
}

type unsignedAttributeBuild struct {
	signer                *Signer
	resolver              *validation.SignatureTrustResolver
	ctx                   cms.UnsignedAttributeContext
	enrichTimestampTokens bool
	enrichTimestampValues bool
}

func (b *unsignedAttributeBuild) build(names []AttributeName) ([]cms.Attribute, error) {
	var attrs []cms.Attribute

	for _, name := range names {
		slog.Info("cades: building unsigned attribute", "name", name)
		attr, err := b.buildOne(name, attrs)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, attr)
		slog.Info("cades: unsigned attribute built", "name", name)
	}

	return attrs, nil
}

func (b *unsignedAttributeBuild) buildOne(name AttributeName, previousAttrs []cms.Attribute) (cms.Attribute, error) {
	switch name {
	case SignatureTimeStampTokenAttr:
		return b.signatureTimeStampToken()
	case CertificateRefsAttr:
		return b.certificateRefs()
	case RevocationRefsAttr:
		return b.revocationRefs()
	case EscTimeStampAttr:
		return b.escTimeStamp(previousAttrs)
	case CertValuesAttr:
		return b.certValues()
	case RevocationValuesAttr:
		return b.revocationValues()
	default:
		return cms.Attribute{}, fmt.Errorf("unsupported unsigned attribute: %s", name)
	}
}

func (b *unsignedAttributeBuild) signatureTimeStampToken() (cms.Attribute, error) {
	if b.signer.TimeStampProvider == nil {
		return cms.Attribute{}, fmt.Errorf("time stamp provider is required")
	}

	return b.stampAndWrap(
		context.Background(),
		b.ctx.Signature,
		"signature timestamp",
		SignatureTimeStampTokenAttribute,
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

	attr, err := CertificateRefsAttribute(refsDER)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to marshal certificate refs attribute: %w", err)
	}

	return attr, nil
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

	attr, err := RevocationRefsAttribute(refsDER)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to marshal revocation refs attribute: %w", err)
	}

	return attr, nil
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

	attr, err := CertValuesAttribute(valuesDER)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to marshal cert values attribute: %w", err)
	}

	return attr, nil
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

	attr, err := RevocationValuesAttribute(valuesDER)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to marshal revocation values attribute: %w", err)
	}

	return attr, nil
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
		EscTimeStampAttribute,
	)
}

func (b *unsignedAttributeBuild) stampAndWrap(
	ctx context.Context,
	input []byte,
	name string,
	factory func([]byte) (cms.Attribute, error),
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

	attr, err := factory(tokenDER)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to marshal %s attribute: %w", name, err)
	}

	return attr, nil
}

func (b *unsignedAttributeBuild) enrichTimestampToken(ctx context.Context, tokenDER []byte) ([]byte, error) {
	if b.resolver == nil {
		slog.Info("cades: timestamp token enrichment not required")
		return tokenDER, nil
	}

	material, err := b.resolver.AddTimestampToken(ctx, tokenDER)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve timestamp trust material: %w", err)
	}
	if material == nil {
		return tokenDER, nil
	}
	if !b.enrichTimestampTokens {
		slog.Info("cades: timestamp token enrichment not required")
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

	// RFC 5126 6.2.1/6.2.2 places TSU certificate/revocation references
	// in the signedData of the relevant timestamp token, under signerInfos
	// unsignedAttrs. The TSA signature is preserved because these attributes
	// are unsigned CMS attributes.
	var certValuesDER, revocationValuesDER []byte
	if b.enrichTimestampValues {
		certValuesDER, err = BuildCertificateValues(material.Chain)
		if err != nil {
			return nil, fmt.Errorf("failed to build timestamp cert values: %w", err)
		}
		revocationValuesDER, err = BuildRevocationValues(material.CRLs)
		if err != nil {
			return nil, fmt.Errorf("failed to build timestamp revocation values: %w", err)
		}
	}

	enriched, err := EnrichTimestampTokenWithRefs(
		tokenDER,
		certRefsDER,
		revocationRefsDER,
		certValuesDER,
		revocationValuesDER,
	)
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
