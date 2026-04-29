package cades

import "encoding/asn1"

var (
	// RFC5035 3 Insert New Section 5.4.1 'Signing Certificate Attribute Definition Version 2'
	OIDSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}

	// RFC5126 5.8.1 signature-policy-identifier
	OIDSignaturePolicyID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 15}

	// RFC5126 5.8.1 id-spq-ets-uri - DOC-ICP-15.03 Versão 9.1 PAG 21
	OIDSignaturePolicyQualifierURI = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 5, 1}
)
