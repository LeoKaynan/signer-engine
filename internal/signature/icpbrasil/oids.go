package icpbrasil

import "encoding/asn1"

var (
	oidSubjectCPF  = asn1.ObjectIdentifier{2, 16, 76, 1, 3, 1}
	oidSubjectCNPJ = asn1.ObjectIdentifier{2, 16, 76, 1, 3, 3}

	oidCertificatePolicyICPBRasilPrefix = asn1.ObjectIdentifier{2, 16, 76, 1, 2}

	// https://repositorio.iti.gov.br/instrucoes-normativas/IN2025_33_DOC_ICP_15.03.htm
	oidPolicyADRB = asn1.ObjectIdentifier{2, 16, 76, 1, 7, 1, 1, 2, 4, 2}
)
