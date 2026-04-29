package icpbrasil

import (
	_ "embed"

	"signer-engine/internal/signature/cades"
)

//go:embed policies/PA_AD_RB_v2_4.der
var adrbPolicyDER []byte

func PolicyADRB() cades.Policy {
	return cadesPolicy{
		oid:      oidPolicyADRB,
		artifact: adrbPolicyDER,
		uri:      "http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_4.der",
	}
}
