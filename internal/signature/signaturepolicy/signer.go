package signaturepolicy

// SignInput carries the bytes a Signer needs to produce a signature. Every
// AdES family accepts the same shape; format-specific fields are encoded in
// the Signer's construction (configuration), not in the per-call input.
//
//   - Data: the primary payload — for PAdES the PDF (signed or not), for
//     CAdES the original document (or the existing attached CMS when
//     auto-detected as co-sign), for XAdES the XML document.
//   - ExistingSignature: optional. When non-empty, signals an explicit co-sign
//     against an already-existing detached signature. Format-specific signers
//     decide how to use it; PAdES ignores it (PAdES serial signing is detected
//     from Data itself).
type SignInput struct {
	Data              []byte
	ExistingSignature []byte
}

// Signer is the unified signing contract that every AdES format implements.
// One method, one shape. The format-specific logic (CAdES vs PAdES vs XAdES)
// lives behind the implementation; the caller does not branch on format.
type Signer interface {
	Sign(input SignInput) ([]byte, error)
}
