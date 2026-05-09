package cades_test

import (
	"testing"

	"signer-engine/internal/app/signing"
	"signer-engine/internal/signature/cades"
	"signer-engine/internal/signature/icpbrasil"
	"signer-engine/internal/tests/fixtures"
	"signer-engine/internal/tests/utils"
)

func TestPKCS12CAdESPAADRAv25(t *testing.T) {
	chain := fixtures.NewChain(t)
	p12 := fixtures.NewPKCS12(t, chain, fixtures.DefaultPKCS12Password)
	content := []byte("signer-engine cades icp-brasil PA_AD_RA_v2_5 e2e")
	signingTime := defaultSigningTime
	policyInfo := requirePolicyInfo(t, icpbrasil.PolicyNamePAADRAv25)
	trust := utils.OpenSSLTrustStore{
		RootsPEM:         chain.RootPEM,
		IntermediatesPEM: chain.IntermediatePEM,
	}

	for _, mode := range []signing.Mode{signing.ModeAttached, signing.ModeDetached} {
		t.Run(string(mode), func(t *testing.T) {
			service := newValidationPolicyService(t, chain, signingTime)

			response, err := service.Sign(signing.Request{
				Data:               content,
				CredentialProvider: signing.CredentialProviderPKCS12,
				PKCS12Data:         p12,
				PKCS12Pass:         fixtures.DefaultPKCS12Password,
				Format:             signing.FormatCades,
				Policy:             icpbrasil.PolicyNamePAADRAv25,
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
			assertUnsignedAttrs(t, signerInfo,
				expectedUnsignedAttr{oid: cades.OIDSignatureTimeStampToken, kind: unsignedAttrTimestamp},
				expectedUnsignedAttr{oid: cades.OIDCertificateRefs, kind: unsignedAttrASN1},
				expectedUnsignedAttr{oid: cades.OIDRevocationRefs, kind: unsignedAttrASN1},
				expectedUnsignedAttr{oid: cades.OIDEscTimeStamp, kind: unsignedAttrTimestamp},
				expectedUnsignedAttr{oid: cades.OIDCertValues, kind: unsignedAttrASN1},
				expectedUnsignedAttr{oid: cades.OIDRevocationValues, kind: unsignedAttrASN1},
				expectedUnsignedAttr{oid: cades.OIDArchiveTimeStampV2, kind: unsignedAttrTimestamp},
			)

			timestampCalls := timestampAttributeCount(policyInfo)
			assertTimeStampProviderCalls(t, service.TimeStampProvider, timestampCalls, signerInfo.Signature)
			assertTrustMaterialExtractorCalls(t, service.TrustMaterialExtractor, timestampCalls)
			assertValidationMaterialAttrs(t, signerInfo, chain, service.TrustMaterialExtractor)
			assertAdvancedTimestampInputs(t, response.Signature, content, mode, service.TimeStampProvider)
		})
	}
}
