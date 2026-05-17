package cades

import (
	"encoding/asn1"
	"signer-engine/internal/signature/cms"
)

// IsAlreadySigned reports whether data is a CMS SignedData with at least one
// existing SignerInfo. Returns false when data is not a CMS at all, so callers
// can use it for transparent first-sign vs co-sign detection.
func IsAlreadySigned(data []byte) bool {
	var ci cms.ContentInfo
	if rest, err := asn1.Unmarshal(data, &ci); err != nil || len(rest) > 0 {
		return false
	}
	var sd cms.SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return false
	}
	return len(sd.SignerInfos) > 0
}
