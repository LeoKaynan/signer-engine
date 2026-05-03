package icpbrasil

import (
	"encoding/asn1"
	"signer-engine/internal/signature/cades"
)

// DOC-ICP-15.03 Versão 9.1 PAG 10 - ETSI TR 102 272 6 Signature policy specification in ASN.1 PAG 12

const (
	PolicyNamePAADRBv24 cades.PolicyName = "PA_AD_RB_v2_4"
	PolicyNamePAADRTv24 cades.PolicyName = "PA_AD_RT_v2_4"
)

type PolicyInfo struct {
	OID                        asn1.ObjectIdentifier
	Hash                       []byte
	URI                        string
	RequiredAttributes         []cades.AttributeName
	RequiredUnsignedAttributes []cades.AttributeName
}

var policies = map[cades.PolicyName]PolicyInfo{
	PolicyNamePAADRBv24: {
		OID: asn1.ObjectIdentifier{2, 16, 76, 1, 7, 1, 1, 2, 4},
		Hash: []byte{
			0x1f, 0x3c, 0x90, 0x4c, 0x44, 0xc3, 0x92, 0xfe,
			0xef, 0x44, 0x7e, 0x21, 0xfa, 0xa7, 0xa0, 0x4e,
			0x85, 0xd9, 0xc0, 0x15, 0x33, 0x46, 0x32, 0x0f,
			0x55, 0x7b, 0x70, 0x42, 0xaf, 0x5d, 0xcf, 0x13,
		},
		URI: "http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_4.der",
		RequiredAttributes: []cades.AttributeName{
			cades.SigningCertificateV2Attr,
			cades.PolicyIdentifierAttr,
		},
		RequiredUnsignedAttributes: nil,
	},
	PolicyNamePAADRTv24: {
		OID: asn1.ObjectIdentifier{2, 16, 76, 1, 7, 1, 2, 2, 4},
		Hash: []byte{
			0xfa, 0x59, 0xdc, 0xa6, 0xd9, 0xc0, 0xe8, 0x08,
			0xeb, 0x73, 0x97, 0xb2, 0xde, 0x80, 0x0c, 0xce,
			0x5b, 0x0e, 0x4d, 0xa2, 0xc4, 0x2e, 0x2e, 0x5e,
			0xf2, 0x49, 0x6a, 0x2c, 0xe6, 0xba, 0xdc, 0xb7,
		},
		URI: "http://politicas.icpbrasil.gov.br/PA_AD_RT_v2_4.der",
		RequiredAttributes: []cades.AttributeName{
			cades.SigningCertificateV2Attr,
			cades.PolicyIdentifierAttr,
		},
		RequiredUnsignedAttributes: []cades.AttributeName{
			cades.SignatureTimeStampTokenAttr,
		},
	},
}
