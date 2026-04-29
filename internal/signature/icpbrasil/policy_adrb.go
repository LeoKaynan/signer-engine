package icpbrasil

import (
	"encoding/asn1"
	"fmt"
	"signer-engine/internal/signature/cades"
	"signer-engine/internal/signature/cms"
)

type adrbPolicy struct {
	icpBrasilBase
}

func PolicyADRB() cades.Policy {
	return adrbPolicy{}
}

func (adrbPolicy) Identifier() asn1.ObjectIdentifier {
	return oidPolicyADRB
}

func (p adrbPolicy) SignedAttributes() []cms.Attribute {
	attr, err := cades.PolicyIdentifierAttribute(p.Identifier(), adrbPolicyDocHash)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal policy identifier attribute: %v", err))
	}

	return []cms.Attribute{attr}
}
