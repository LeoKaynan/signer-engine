package icpbrasil

import (
	_ "embed"

	"signer-engine/internal/signature/cades"
)

//go:embed policies/PA_AD_RB_v2_4.der
var cadesADRBPolicyDER []byte

const cadesADRBPolicyURI = "http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_4.der"

func PolicyADRB() cades.Policy {
	return cadesPolicy{
		oid:      oidCAdESPolicyADRB,
		artifact: cadesADRBPolicyDER,
		uri:      cadesADRBPolicyURI,
	}
}
