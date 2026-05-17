package cms

import "encoding/asn1"

// RawAttribute wraps a pre-marshaled DER blob in a CMS Attribute carrying the
// given identifier. It is the single building block used by every AdES family
// (CAdES/PAdES/XAdES via CMS) for opaque-payload signed and unsigned attributes.
//
// Validation (non-empty DER, well-formed ASN.1) is the caller's responsibility:
// the empty check is trivial at the call site and any malformed DER will fail
// when the enclosing SignedData is marshaled, so we do not duplicate it here.
func RawAttribute(id asn1.ObjectIdentifier, der []byte) Attribute {
	return Attribute{
		AttrType: id,
		AttrValues: []asn1.RawValue{
			{FullBytes: der},
		},
	}
}
