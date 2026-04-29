package signing

type Format string

const (
	FormatCades Format = "cades"
	FormatPades Format = "pades"
	FormatXades Format = "xades"
)

type Policy string

const (
	PolicyICPBRasilADRB Policy = "icpbrasil-adrb"
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
	Policy Policy
	Mode   Mode
}

type Response struct {
	Signature []byte
}
