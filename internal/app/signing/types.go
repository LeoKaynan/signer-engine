package signing

import "signer-engine/internal/signature/cades"

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

type Request struct {
	Data []byte

	CredentialProvider CredentialProvider
	PKCS12Data         []byte
	PKCS12Pass         string

	Format Format
	Policy cades.PolicyName
	Mode   Mode
}

type Response struct {
	Signature []byte
}
