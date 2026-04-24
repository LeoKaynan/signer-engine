package constants

import "encoding/asn1"

var (
	// RFC5652 3 General Syntax
	OIDContentInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 6}

	// RFC5652 4 Data Content Type
	OIDData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}

	// RFC5652 5.1  SignedData Type
	OIDSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	// RFC5652 11.1 Content Type
	OIDContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}

	// RFC5652 11.2 Message Digest
	OIDMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	// RFC5652 11.3 Signing Time
	OIDSigningTime = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}

	// RFC3279 2.3.1 RSA Keys
	OIDRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

	// RFC4055 2.1 One-way Hash Functions
	OIDSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	OIDSHA224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	OIDSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
)
