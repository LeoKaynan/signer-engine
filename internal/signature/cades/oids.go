package cades

import "encoding/asn1"

var (
	// RFC5035 3 Insert New Section 5.4.1 'Signing Certificate Attribute Definition Version 2'
	OIDSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}

	// RFC5126 5.8.1 signature-policy-identifier
	OIDSignaturePolicyID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 15}

	// RFC5126 5.8.1 id-spq-ets-uri - DOC-ICP-15.03 Versão 9.1 PAG 21
	OIDSignaturePolicyQualifierURI = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 5, 1}

	// RFC3161 APPENDIX A - Signature Time-stamp attribute using CMS
	OIDSignatureTimeStampToken = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

	// RFC5126 6.2.1 complete-certificate-references Attribute Definition
	OIDCertificateRefs = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 21}

	// RFC5126 6.2.2 complete-revocation-references Attribute Definition
	OIDRevocationRefs = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 22}

	// RFC5126 6.3.5 CAdES-C-time-stamp Attribute Definition
	OIDEscTimeStamp = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 25}

	// RFC5126 6.3.3  certificate-values Attribute Definition
	OIDCertValues = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 23}

	// RFC5126 6.3.4  revocation-values Attribute Definition
	OIDRevocationValues = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 24}

	// RFC5126 6.4.1  archive-time-stamp Attribute Definition
	OIDArchiveTimeStampV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 48}
)
