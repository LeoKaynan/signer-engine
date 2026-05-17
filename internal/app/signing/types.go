package signing

import (
	"signer-engine/internal/signature/signaturepolicy"
	"signer-engine/internal/signer"
	"signer-engine/internal/tsa"
	"signer-engine/internal/validation"
)

type Format string

const (
	FormatCades Format = "cades"
	FormatPades Format = "pades"
	FormatXades Format = "xades"
)

type Mode string

const (
	ModeAttached Mode = "attached"
	ModeDetached Mode = "detached"
)

type CredentialProvider string

const (
	CredentialProviderPKCS12 CredentialProvider = "pkcs12"
)

// Request describes a signing job. Whether the operation is a fresh signature
// or a co-signature is inferred from the inputs:
//   - CAdES detached co-sign: set ExistingSignature to the existing CMS and
//     Data to the original document.
//   - CAdES attached co-sign: set Data to the existing CMS (auto-detected via
//     cades.IsAlreadySigned).
//   - PAdES serial signing: set Data to the already-signed PDF; pades.Signer
//     auto-detects via the DocMDP marker.
type Request struct {
	Data              []byte
	ExistingSignature []byte

	CredentialProvider CredentialProvider
	PKCS12Data         []byte
	PKCS12Pass         string

	Format Format
	Policy signaturepolicy.PolicyName
	Mode   Mode
}

type Response struct {
	Signature []byte
}

// SignerDeps groups the cross-format dependencies that every signer needs.
// Each factory wires these into the concrete Signer it builds.
type SignerDeps struct {
	TimeStampProvider      tsa.Provider
	TrustMaterialExtractor validation.TrustMaterialExtractor
	Clock                  signaturepolicy.Clock
}

// SignerFactory builds a concrete signaturepolicy.Signer for one Request.
// One factory per Format is registered in Service.SignerFactories. Adding a
// new format (e.g. XAdES) means registering one more factory — Service.Sign
// stays untouched.
type SignerFactory func(deps SignerDeps, credential signer.Credential, request Request) (signaturepolicy.Signer, error)

// CredentialResolver builds a signer.Credential from one Request. One resolver
// per CredentialProvider is registered in Service.CredentialResolvers. Adding
// a new provider (e.g. HSM) means registering one more resolver.
type CredentialResolver func(request Request) (signer.Credential, error)
