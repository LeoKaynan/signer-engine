package icpbrasil

import (
	"encoding/asn1"
	"signer-engine/internal/signature/cades"
)

// DOC-ICP-15.03 Versão 9.1 PAG 10 - ETSI TR 102 272 6 Signature policy specification in ASN.1 PAG 12

const (
	PolicyNamePAADRBv24 cades.PolicyName = "PA_AD_RB_v2_4"
	PolicyNamePAADRTv24 cades.PolicyName = "PA_AD_RT_v2_4"
	PolicyNamePAADRVv24 cades.PolicyName = "PA_AD_RV_v2_4"
	PolicyNamePAADRCv24 cades.PolicyName = "PA_AD_RC_v2_4"
	PolicyNamePAADRAv25 cades.PolicyName = "PA_AD_RA_v2_5"
)

type PolicyInfo struct {
	OID                        asn1.ObjectIdentifier
	Hash                       []byte
	URI                        string
	RequiredAttributes         []cades.AttributeName
	RequiredUnsignedAttributes []cades.AttributeName
}

func PolicyInfoByName(name cades.PolicyName) (PolicyInfo, bool) {
	info, ok := policies[name]
	if !ok {
		return PolicyInfo{}, false
	}

	return PolicyInfo{
		OID:                        append(asn1.ObjectIdentifier(nil), info.OID...),
		Hash:                       append([]byte(nil), info.Hash...),
		URI:                        info.URI,
		RequiredAttributes:         append([]cades.AttributeName(nil), info.RequiredAttributes...),
		RequiredUnsignedAttributes: append([]cades.AttributeName(nil), info.RequiredUnsignedAttributes...),
	}, true
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
	PolicyNamePAADRVv24: {
		OID: asn1.ObjectIdentifier{2, 16, 76, 1, 7, 1, 3, 2, 4},
		Hash: []byte{
			0xac, 0x8d, 0x32, 0x99, 0x18, 0x9a, 0x58, 0xf8,
			0x8e, 0xc9, 0x38, 0xd1, 0xb5, 0x91, 0x8f, 0x65,
			0xbd, 0x9d, 0x1b, 0x22, 0xe1, 0xd1, 0xa3, 0x2b,
			0x99, 0x8f, 0x3f, 0xdf, 0x07, 0xec, 0x33, 0x42,
		},
		URI: "http://politicas.icpbrasil.gov.br/PA_AD_RV_v2_4.der",
		RequiredAttributes: []cades.AttributeName{
			cades.SigningCertificateV2Attr,
			cades.PolicyIdentifierAttr,
		},
		RequiredUnsignedAttributes: []cades.AttributeName{
			cades.SignatureTimeStampTokenAttr,
			cades.CertificateRefsAttr,
			cades.RevocationRefsAttr,
			cades.EscTimeStampAttr,
		},
	},
	PolicyNamePAADRCv24: {
		OID: asn1.ObjectIdentifier{2, 16, 76, 1, 7, 1, 4, 2, 4},
		Hash: []byte{
			0xab, 0x0d, 0xd3, 0x37, 0x58, 0x0f, 0x7c, 0xcd,
			0x62, 0x44, 0xe3, 0x0f, 0x2a, 0x29, 0xf2, 0xe9,
			0x76, 0x14, 0xad, 0x41, 0x18, 0x38, 0xa0, 0xa1,
			0x17, 0x9d, 0x47, 0x95, 0x04, 0xf5, 0x52, 0x2b,
		},
		URI: "http://politicas.icpbrasil.gov.br/PA_AD_RC_v2_4.der",
		RequiredAttributes: []cades.AttributeName{
			cades.SigningCertificateV2Attr,
			cades.PolicyIdentifierAttr,
		},
		RequiredUnsignedAttributes: []cades.AttributeName{
			cades.SignatureTimeStampTokenAttr,
			cades.CertificateRefsAttr,
			cades.RevocationRefsAttr,
			cades.EscTimeStampAttr,
			cades.CertValuesAttr,
			cades.RevocationValuesAttr,
		},
	},
	PolicyNamePAADRAv25: {
		OID: asn1.ObjectIdentifier{2, 16, 76, 1, 7, 1, 5, 2, 5},
		Hash: []byte{
			0x05, 0x31, 0xee, 0x33, 0x8a, 0xcb, 0x53, 0x36,
			0x4c, 0x8b, 0x31, 0x6a, 0x11, 0xd9, 0x04, 0x23,
			0xee, 0x33, 0xe7, 0x14, 0xcb, 0x36, 0x5d, 0x9c,
			0x45, 0x62, 0xb9, 0x0f, 0xa4, 0x7d, 0x90, 0x99,
		},
		URI: "http://politicas.icpbrasil.gov.br/PA_AD_RA_v2_5.der",
		RequiredAttributes: []cades.AttributeName{
			cades.SigningCertificateV2Attr,
			cades.PolicyIdentifierAttr,
		},
		RequiredUnsignedAttributes: []cades.AttributeName{
			cades.SignatureTimeStampTokenAttr,
			cades.CertificateRefsAttr,
			cades.RevocationRefsAttr,
			cades.EscTimeStampAttr,
			cades.CertValuesAttr,
			cades.RevocationValuesAttr,
			cades.ArchiveTimeStampV2Attr,
		},
	},
}
