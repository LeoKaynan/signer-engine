package signing_test

import (
	"testing"

	"signer-engine/internal/app/signing"
	"signer-engine/internal/signature/icpbrasil"
	"signer-engine/internal/tests/fixtures"
	"signer-engine/internal/tests/utils"
)

func TestSigningServiceRejectsInvalidRequests(t *testing.T) {
	chain := fixtures.NewChain(t)
	p12 := fixtures.NewPKCS12(t, chain, fixtures.DefaultPKCS12Password)

	baseRequest := signing.Request{
		Data:               []byte("signer-engine invalid request e2e"),
		CredentialProvider: signing.CredentialProviderPKCS12,
		PKCS12Data:         p12,
		PKCS12Pass:         fixtures.DefaultPKCS12Password,
		Format:             signing.FormatCades,
		Policy:             icpbrasil.PolicyNamePAADRBv24,
		Mode:               signing.ModeAttached,
	}

	tests := []struct {
		name          string
		mutate        func(*signing.Request)
		wantSubstring string
	}{
		{
			name: "unknown credential provider",
			mutate: func(request *signing.Request) {
				request.CredentialProvider = signing.CredentialProvider("invalid")
			},
			wantSubstring: "unsupported credential provider: invalid",
		},
		{
			name: "unknown format",
			mutate: func(request *signing.Request) {
				request.Format = signing.Format("invalid")
			},
			wantSubstring: "unsupported format: invalid",
		},
		{
			name: "unknown CAdES mode",
			mutate: func(request *signing.Request) {
				request.Mode = signing.Mode("invalid")
			},
			wantSubstring: "unsupported cades mode: invalid",
		},
		{
			name: "unknown ICP-Brasil policy",
			mutate: func(request *signing.Request) {
				request.Policy = "PA_AD_INEXISTENTE"
			},
			wantSubstring: "policy not found: PA_AD_INEXISTENTE",
		},
	}

	service := signing.Service{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := baseRequest
			tt.mutate(&request)

			_, err := service.Sign(request)
			utils.RequireErrorContains(t, err, tt.wantSubstring)
		})
	}
}
