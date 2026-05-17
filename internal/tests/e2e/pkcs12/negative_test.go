package pkcs12_test

import (
	"testing"

	"signer-engine/internal/app/signing"
	"signer-engine/internal/signature/icpbrasil"
	"signer-engine/internal/tests/fixtures"
	"signer-engine/internal/tests/utils"
)

func TestPKCS12ProviderRejectsInvalidInput(t *testing.T) {
	chain := fixtures.NewChain(t)
	p12 := fixtures.NewPKCS12(t, chain, fixtures.DefaultPKCS12Password)

	tests := []struct {
		name       string
		p12        []byte
		password   string
		wantErrSub string
	}{
		{
			name:       "wrong password",
			p12:        p12,
			password:   "wrong-password",
			wantErrSub: "failed to decode chain",
		},
		{
			name:       "corrupted bytes",
			p12:        []byte("nao-e-pkcs12"),
			password:   fixtures.DefaultPKCS12Password,
			wantErrSub: "failed to decode chain",
		},
		{
			name:       "empty bytes",
			p12:        nil,
			password:   fixtures.DefaultPKCS12Password,
			wantErrSub: "failed to decode chain",
		},
	}

	service := signing.DefaultService()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.Sign(signing.Request{
				Data:               []byte("signer-engine pkcs12 negative e2e"),
				CredentialProvider: signing.CredentialProviderPKCS12,
				PKCS12Data:         tt.p12,
				PKCS12Pass:         tt.password,
				Format:             signing.FormatCades,
				Policy:             icpbrasil.PolicyNamePAADRB,
				Mode:               signing.ModeAttached,
			})
			utils.RequireErrorContains(t, err, tt.wantErrSub)
		})
	}
}
