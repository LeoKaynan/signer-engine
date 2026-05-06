package cades

import (
	"context"
	"crypto/x509"
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
		builder := unsignedAttributeBuild{
			signer:                s,
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
	ctx                   cms.UnsignedAttributeContext
	refs                  *validation.Refs
	timestampCerts        []*x509.Certificate
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

	slog.Info("cades: requesting signature timestamp")
	token, err := b.signer.TimeStampProvider.Stamp(
		context.Background(),
		b.ctx.Signature,
		b.ctx.HashAlg,
	)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to stamp signature: %w", err)
	}
	slog.Info("cades: signature timestamp received", "bytes", len(token.TokenDER))

	tokenDER, err := b.enrichTimestampToken(token.TokenDER)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to enrich signature timestamp token: %w", err)
	}

	attr, err := SignatureTimeStampTokenAttribute(tokenDER)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to marshal signature time stamp token attribute: %w", err)
	}

	return attr, nil
}

func (b *unsignedAttributeBuild) validationRefs() (*validation.Refs, error) {
	if b.refs != nil {
		slog.Info("cades: reusing validation refs")
		return b.refs, nil
	}
	if b.signer.ValidationProvider == nil {
		return nil, fmt.Errorf("validation provider is required")
	}

	chain := appendCertificateSet(b.signer.Credential.Chain(), b.timestampCerts...)

	slog.Info("cades: building validation refs", "chain_certs", len(chain))
	refs, err := b.signer.ValidationProvider.BuildRefs(
		context.Background(),
		b.signer.Credential.Certificate(),
		chain,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build validation refs: %w", err)
	}

	b.refs = refs
	slog.Info("cades: validation refs built",
		"certificate_refs", len(refs.CertificateRefs),
		"revocation_refs", len(refs.RevocationRefs),
		"certificate_values", len(refs.CertificateValues),
		"revocation_values", len(refs.RevocationValues),
	)
	return refs, nil
}

func (b *unsignedAttributeBuild) certificateRefs() (cms.Attribute, error) {
	refs, err := b.validationRefs()
	if err != nil {
		return cms.Attribute{}, err
	}

	attr, err := CertificateRefsAttribute(refs.CertificateRefs)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to marshal certificate refs attribute: %w", err)
	}

	return attr, nil
}

func (b *unsignedAttributeBuild) revocationRefs() (cms.Attribute, error) {
	refs, err := b.validationRefs()
	if err != nil {
		return cms.Attribute{}, err
	}

	attr, err := RevocationRefsAttribute(refs.RevocationRefs)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to marshal revocation refs attribute: %w", err)
	}

	return attr, nil
}

func (b *unsignedAttributeBuild) certValues() (cms.Attribute, error) {
	refs, err := b.validationRefs()
	if err != nil {
		return cms.Attribute{}, err
	}

	attr, err := CertValuesAttribute(refs.CertificateValues)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to marshal cert values attribute: %w", err)
	}

	return attr, nil
}

func (b *unsignedAttributeBuild) revocationValues() (cms.Attribute, error) {
	refs, err := b.validationRefs()
	if err != nil {
		return cms.Attribute{}, err
	}

	attr, err := RevocationValuesAttribute(refs.RevocationValues)
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

	slog.Info("cades: requesting esc timestamp", "input_bytes", len(input))
	token, err := b.signer.TimeStampProvider.Stamp(
		context.Background(),
		input,
		b.ctx.HashAlg,
	)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to stamp esc timestamp input: %w", err)
	}
	slog.Info("cades: esc timestamp received", "bytes", len(token.TokenDER))

	tokenDER, err := b.enrichTimestampToken(token.TokenDER)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to enrich esc timestamp token: %w", err)
	}

	attr, err := EscTimeStampAttribute(tokenDER)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to marshal esc timestamp attribute: %w", err)
	}

	return attr, nil
}

func (b *unsignedAttributeBuild) enrichTimestampToken(tokenDER []byte) ([]byte, error) {
	info := TimestampTokenCertificateInfo(tokenDER)
	if info.Signer == nil {
		slog.Info("cades: timestamp token has no signer certificate info")
		return tokenDER, nil
	}

	b.timestampCerts = appendCertificateSet(b.timestampCerts, info.All...)

	if !b.enrichTimestampTokens {
		slog.Info("cades: timestamp token enrichment not required")
		return tokenDER, nil
	}
	if b.signer.ValidationProvider == nil {
		return nil, fmt.Errorf("validation provider is required")
	}

	slog.Info("cades: building timestamp validation refs", "chain_certs", len(info.Chain))
	refs, err := b.signer.ValidationProvider.BuildRefs(
		context.Background(),
		info.Signer,
		info.Chain,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build timestamp validation refs: %w", err)
	}

	// RFC 5126 6.2.1/6.2.2 places TSU certificate/revocation references
	// in the signedData of the relevant timestamp token, under signerInfos
	// unsignedAttrs. The TSA signature is preserved because these attributes
	// are unsigned CMS attributes.
	var certValuesDER, revocationValuesDER []byte
	if b.enrichTimestampValues {
		certValuesDER = refs.CertificateValues
		revocationValuesDER = refs.RevocationValues
	}

	enriched, err := EnrichTimestampTokenWithRefs(
		tokenDER,
		refs.CertificateRefs,
		refs.RevocationRefs,
		certValuesDER,
		revocationValuesDER,
	)
	if err != nil {
		return nil, err
	}
	slog.Info("cades: timestamp token enriched",
		"certificate_refs", len(refs.CertificateRefs),
		"revocation_refs", len(refs.RevocationRefs),
		"certificate_values", len(certValuesDER),
		"revocation_values", len(revocationValuesDER),
	)

	return enriched, nil
}
