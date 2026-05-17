package cms

import "encoding/asn1"

// Content-type OIDs (RFC 5652 §3, §4, §5.1). These identify CMS structures —
// not signed/unsigned attributes — and keep the OID* prefix.
var (
	// RFC5652 3 General Syntax
	OIDContentInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 6}

	// RFC5652 4 Data Content Type
	OIDData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}

	// RFC5652 5.1 SignedData Type
	OIDSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
)

// Attribute identifiers (id-aa-*, id-* from RFCs 5652/5035/5126/3161).
// These name CMS signed and unsigned attributes used by every AdES family
// that builds on top of CMS (CAdES, PAdES). They use the Id* prefix to mirror
// the ASN.1 module names from the source RFCs.
var (
	// RFC5652 11.1 Content Type
	IdContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}

	// RFC5652 11.2 Message Digest
	IdMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	// RFC5652 11.3 Signing Time
	IdSigningTime = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)
