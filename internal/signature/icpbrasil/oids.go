package icpbrasil

import "encoding/asn1"

var (
	oidCertificatePolicyICPBRasilPrefix = asn1.ObjectIdentifier{2, 16, 76, 1, 2}

	// https://repositorio.iti.gov.br/instrucoes-normativas/IN2025_33_DOC_ICP_15.03.htm
	oidCAdESPolicyADRB = asn1.ObjectIdentifier{2, 16, 76, 1, 7, 1, 1, 2, 4}
)
