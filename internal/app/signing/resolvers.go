package signing

import (
	"fmt"
	"signer-engine/internal/signer"
	"signer-engine/internal/signer/pkcs12"
)

func credentialResolver(request Request) (signer.Credential, error) {
	switch request.CredentialProvider {
	case CredentialProviderPKCS12:
		return pkcs12.NewCredentialFromBytes(request.PKCS12Data, request.PKCS12Pass)
	default:
		return nil, fmt.Errorf("unsupported credential provider: %s", request.CredentialProvider)
	}
}

func cadesModeResolver(mode Mode) (bool, error) {
	switch mode {
	case ModeAttached:
		return false, nil
	case ModeDetached:
		return true, nil
	}
	return false, fmt.Errorf("unsupported cades mode: %s", mode)
}
