package cades

import "signer-engine/internal/signature/cms"

// RFC5035 4 Insert New Section 5.4.1.1 'Certificate Identification Version 2'
type ESSCertIDv2 struct {
	// hashAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256}
	HashAlgorithm *cms.AlgorithmIdentifier `asn1:"optional"`
	CertHash      []byte
}

// RFC5035 3 Insert New Section 5.4.1 'Signing Certificate Attribute Definition
type SigningCertificateV2 struct {
	Certs []ESSCertIDv2
	// RFC5280 4.2.1.4 Certificate Policies
	// Policies []PolicyInformation `asn1:"optional"`
}
