package icpbrasil

import (
	"encoding/asn1"
	"errors"
	"fmt"

	"signer-engine/internal/signature/cades"
	"signer-engine/internal/signature/cms"
)

var _ cades.Policy = (*cadesPolicy)(nil)

type cadesPolicy struct {
	icpBrasilBase

	info PolicyInfo
}

func (p cadesPolicy) Identifier() asn1.ObjectIdentifier {
	return p.info.OID
}

func (p cadesPolicy) SignedAttributes(ctx cades.SigningContext) ([]cms.Attribute, error) {
	if ctx.Certificate == nil {
		return nil, errors.New("certificate is required")
	}

	attrs := []cms.Attribute{}

	for _, required := range p.info.RequiredAttributes {
		switch required {
		case cades.SigningCertificateV2Attr:
			attr, err := cades.SigningCertificateV2Attribute(ctx.Certificate)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal signing certificate v2 attribute: %w", err)
			}
			attrs = append(attrs, attr)
		case cades.PolicyIdentifierAttr:
			attr, err := cades.PolicyIdentifierAttribute(p.Identifier(), p.info.Hash, p.info.URI)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal policy identifier attribute: %w", err)
			}
			attrs = append(attrs, attr)
		default:
			return nil, fmt.Errorf("unsupported attribute: %s", required)
		}
	}

	return attrs, nil
}

func (p cadesPolicy) UnsignedAttributeNames() []cades.AttributeName {
	return append([]cades.AttributeName(nil), p.info.RequiredUnsignedAttributes...)
}

func NewPolicy(name cades.PolicyName) (cades.Policy, error) {
	return newPolicy(name, icpBrasilBase{})
}

func NewPolicyWithRootsPEM(name cades.PolicyName, rootsPEM []byte) (cades.Policy, error) {
	roots := append([]byte(nil), rootsPEM...)
	return newPolicy(name, icpBrasilBase{
		rootPEM: func() ([]byte, error) {
			return append([]byte(nil), roots...), nil
		},
	})
}

func newPolicy(name cades.PolicyName, base icpBrasilBase) (cades.Policy, error) {
	info, ok := policies[name]
	if !ok {
		return nil, fmt.Errorf("policy not found: %s", name)
	}
	return &cadesPolicy{icpBrasilBase: base, info: info}, nil
}
