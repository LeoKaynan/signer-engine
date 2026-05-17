package cades

import "encoding/asn1"

// CAdES unsigned-attribute identifiers (RFC 5126 / ETSI TS 101 733).
// Use the Id* prefix to mirror the ASN.1 names (id-aa-ets-*) from the spec.
var (
	// RFC5126 6.2.1 — id-aa-ets-certificateRefs
	IdCertificateRefs = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 21}

	// RFC5126 6.2.2 — id-aa-ets-revocationRefs
	IdRevocationRefs = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 22}

	// RFC5126 6.3.5 — id-aa-ets-escTimeStamp (CAdES-C time-stamp)
	IdEscTimeStamp = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 25}

	// RFC5126 6.3.3 — id-aa-ets-certValues
	IdCertValues = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 23}

	// RFC5126 6.3.4 — id-aa-ets-revocationValues
	IdRevocationValues = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 24}

	// RFC5126 6.4.1 — id-aa-ets-archiveTimestampV2
	IdArchiveTimeStampV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 48}
)
