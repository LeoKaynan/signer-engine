package icpbrasil

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"signer-engine/internal/signature/cades"
	"signer-engine/internal/signature/cms"
	"signer-engine/internal/signature/pades"
	"signer-engine/internal/signature/signaturepolicy"
)

var _ cades.Policy = (*cadesPolicy)(nil)
var _ pades.Policy = (*padesPolicy)(nil)

type cadesPolicy struct {
	icpBrasilBase
	info PolicyInfo
}

func (p cadesPolicy) Identifier() asn1.ObjectIdentifier {
	return p.info.OID
}

func (p cadesPolicy) SignedAttributes(ctx cades.SigningContext) ([]cms.Attribute, error) {
	return buildICPBrasilSignedAttrs(ctx.Certificate, p.info.policyBase)
}

func (p cadesPolicy) Level() signaturepolicy.Level {
	return p.info.Level
}

func NewCAdESPolicy(name signaturepolicy.PolicyName) (cades.Policy, error) {
	return newCAdESPolicy(name, icpBrasilBase{})
}

func NewCAdESPolicyWithRootsPEM(name signaturepolicy.PolicyName, rootsPEM []byte) (cades.Policy, error) {
	roots := append([]byte(nil), rootsPEM...)
	return newCAdESPolicy(name, icpBrasilBase{
		rootPEM: func() ([]byte, error) {
			return append([]byte(nil), roots...), nil
		},
	})
}

func newCAdESPolicy(name signaturepolicy.PolicyName, base icpBrasilBase) (cades.Policy, error) {
	info, ok := cadesPolicies[name]
	if !ok {
		return nil, fmt.Errorf("cades policy not found: %s", name)
	}
	return &cadesPolicy{icpBrasilBase: base, info: info}, nil
}

func NewPAdESPolicy(name signaturepolicy.PolicyName) (pades.Policy, error) {
	info, ok := padesPolicies[name]
	if !ok {
		return nil, fmt.Errorf("pades policy not found: %s", name)
	}
	return &padesPolicy{icpBrasilBase: icpBrasilBase{}, info: info}, nil
}

type padesPolicy struct {
	icpBrasilBase
	info PolicyInfo
}

func (p padesPolicy) Identifier() asn1.ObjectIdentifier {
	return p.info.OID
}

func (p padesPolicy) Level() signaturepolicy.Level {
	return p.info.Level
}

func (p padesPolicy) SignedAttributes(ctx pades.SigningContext) ([]cms.Attribute, error) {
	return buildICPBrasilSignedAttrs(ctx.Certificate, p.info.policyBase)
}

// PBADArtifactURLs returns the URLs of the policy artifact, the LPA artifact,
// and the LPA signature for this PAdES policy. Used to populate the PBAD_*
// entries of the PAdES DSS (DOC-ICP-15.03 Anexo 4).
func (p padesPolicy) PBADArtifactURLs() (policyURL, lpaArtifactURL, lpaSignatureURL string) {
	return p.info.URI, lpaPAdESArtifactURL, lpaPAdESSignatureURL
}

const (
	lpaPAdESArtifactURL  = "http://politicas.icpbrasil.gov.br/LPA_PAdES.der"
	lpaPAdESSignatureURL = "http://politicas.icpbrasil.gov.br/LPA_PAdES.p7s"
)

// buildICPBrasilSignedAttrs builds the two mandatory ICP-Brasil CMS signed
// attributes (signing-certificate-v2 and signature-policy-identifier) from
// the given certificate and policy metadata.
func buildICPBrasilSignedAttrs(cert *x509.Certificate, base policyBase) ([]cms.Attribute, error) {
	if cert == nil {
		return nil, errors.New("certificate is required")
	}
	sigCertAttr, err := cms.SigningCertificateV2Attribute(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to build signing certificate v2 attribute: %w", err)
	}
	policyAttr, err := cms.PolicyIdentifierAttribute(base.OID, base.Hash, base.URI)
	if err != nil {
		return nil, fmt.Errorf("failed to build policy identifier attribute: %w", err)
	}
	return []cms.Attribute{sigCertAttr, policyAttr}, nil
}
