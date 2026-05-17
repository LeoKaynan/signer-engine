package cades_test

import (
	"testing"

	"signer-engine/internal/app/signing"
	"signer-engine/internal/signature/cms"
	"signer-engine/internal/signature/icpbrasil"
	"signer-engine/internal/tests/fixtures"
	"signer-engine/internal/tests/utils"
)

func TestPKCS12CAdESPAADRT(t *testing.T) {
	chain := fixtures.NewChain(t)
	p12 := fixtures.NewPKCS12(t, chain, fixtures.DefaultPKCS12Password)
	content := []byte("signer-engine cades icp-brasil PA_AD_RT e2e")
	signingTime := fixtures.DefaultSigningTime
	policyInfo := requirePolicyInfo(t, icpbrasil.PolicyNamePAADRT)
	trust := utils.OpenSSLTrustStore{
		RootsPEM:         chain.RootPEM,
		IntermediatesPEM: chain.IntermediatePEM,
	}

	for _, mode := range []signing.Mode{signing.ModeAttached, signing.ModeDetached} {
		t.Run(string(mode), func(t *testing.T) {
			service := newTimeStampPolicyService(t, chain, signingTime)

			response, err := service.Sign(signing.Request{
				Data:               content,
				CredentialProvider: signing.CredentialProviderPKCS12,
				PKCS12Data:         p12,
				PKCS12Pass:         fixtures.DefaultPKCS12Password,
				Format:             signing.FormatCades,
				Policy:             icpbrasil.PolicyNamePAADRT,
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
			timestampAttr := utils.RequireOnlyUnsignedAttr(t, signerInfo, cms.IdSignatureTimeStampToken)
			utils.AssertTimestampTokenAttribute(t, timestampAttr)
			assertTimeStampProviderCalls(t, service.TimeStampProvider, timestampAttributeCount(policyInfo), signerInfo.Signature)
		})
	}
}
