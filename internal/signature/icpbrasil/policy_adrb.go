package icpbrasil

import (
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"signer-engine/internal/signature/cades"
	"signer-engine/internal/signature/cms"
)

type adrbPolicy struct {
	icpBrasilBase
}

func PolicyADRB() cms.Policy {
	return adrbPolicy{}
}

func (adrbPolicy) Identifier() asn1.ObjectIdentifier {
	// https://repositorio.iti.gov.br/instrucoes-normativas/IN2025_33_DOC_ICP_15.03.htm
	return asn1.ObjectIdentifier{2, 16, 76, 1, 7, 1, 1, 2, 4, 2}
}

// http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_4der-sha256.txt
var adrbPolicyDocHash = mustDecodeHex(
	"25f148b0828c0ba93695742469566fcc4d1618aa0c20cac56ae72b3419ecee6b",
)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("invalid hex constant: %v", err))
	}
	return b
}

func (p adrbPolicy) SignedAttributes() []cms.Attribute {
	attr, err := cades.PolicyIdentifierAttribute(p.Identifier(), adrbPolicyDocHash)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal policy identifier attribute: %v", err))
	}

	return []cms.Attribute{attr}
}
