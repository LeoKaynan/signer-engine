package cades

import (
	"signer-engine/internal/signature/cms"
	"signer-engine/internal/signature/signaturepolicy"
)

type Policy interface {
	signaturepolicy.Policy
	SignedAttributes() []cms.Attribute
}
