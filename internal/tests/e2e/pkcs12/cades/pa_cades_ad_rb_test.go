package cades_test

import (
	"testing"

	"signer-engine/internal/app/signing"
	"signer-engine/internal/signature/icpbrasil"
	"signer-engine/internal/tests/fixtures"
	"signer-engine/internal/tests/utils"
)

func TestPKCS12CAdESPAADRB(t *testing.T) {
	chain := fixtures.NewChain(t)
	p12 := fixtures.NewPKCS12(t, chain, fixtures.DefaultPKCS12Password)
	content := []byte("signer-engine cades icp-brasil PA_AD_RB e2e")
	signingTime := fixtures.DefaultSigningTime
	policyInfo := requirePolicyInfo(t, icpbrasil.PolicyNamePAADRB)
	trust := utils.OpenSSLTrustStore{
		RootsPEM:         chain.RootPEM,
		IntermediatesPEM: chain.IntermediatePEM,
	}
	service := newPolicyService(t, chain, signingTime)

	for _, mode := range []signing.Mode{signing.ModeAttached, signing.ModeDetached} {
		t.Run(string(mode), func(t *testing.T) {
			response, err := service.Sign(signing.Request{
				Data:               content,
				CredentialProvider: signing.CredentialProviderPKCS12,
				PKCS12Data:         p12,
				PKCS12Pass:         fixtures.DefaultPKCS12Password,
				Format:             signing.FormatCades,
				Policy:             icpbrasil.PolicyNamePAADRB,
				Mode:               mode,
			})
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}
			if len(response.Signature) == 0 {
				t.Fatal("expected signature bytes")
			}

			utils.VerifyCAdESWithOpenSSL(t, response.Signature, content, mode, trust)
			signerInfo := assertCommonCAdES(t, response.Signature, content, mode, chain, signingTime, policyInfo)
			utils.RequireNoUnsignedAttrs(t, signerInfo, "PA_AD_RB")
		})
	}
}
