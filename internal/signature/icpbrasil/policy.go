package icpbrasil

import (
	"encoding/asn1"
	"errors"
	"fmt"

	"signer-engine/internal/signature/cades"
	"signer-engine/internal/signature/cms"
)

type cadesPolicy struct {
	icpBrasilBase

	oid      asn1.ObjectIdentifier
	artifact []byte
	uri      string
}

func (p cadesPolicy) Identifier() asn1.ObjectIdentifier {
	return p.oid
}

func (p cadesPolicy) SignedAttributes() []cms.Attribute {
	digest, err := policyDigestFromDER(p.artifact)
	if err != nil {
		panic(fmt.Sprintf("failed to extract policy digest: %v", err))
	}

	attr, err := cades.PolicyIdentifierAttribute(p.Identifier(), digest, p.uri)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal policy identifier attribute: %v", err))
	}

	return []cms.Attribute{attr}
}

// DOC-ICP-15.03 Versão 9.1 PAG 10 - ETSI TR 102 272 6 Signature policy specification in ASN.1 PAG 12
func policyDigestFromDER(data []byte) ([]byte, error) {
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(data, &outer); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy DER: %w", err)
	}
	rest := outer.Bytes
	for i := range 2 {
		var ignored asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &ignored)
		if err != nil {
			return nil, fmt.Errorf("failed to skip policy header sequence %d: %w", i+1, err)
		}
	}
	var digest []byte
	if _, err := asn1.Unmarshal(rest, &digest); err != nil {
		return nil, fmt.Errorf("failed to extract policy digest: %w", err)
	}
	if len(digest) == 0 {
		return nil, errors.New("empty policy digest")
	}
	return digest, nil
}
