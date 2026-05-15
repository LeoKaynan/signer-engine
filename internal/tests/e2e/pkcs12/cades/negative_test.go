package cades_test

import (
	"testing"

	"signer-engine/internal/app/signing"
	"signer-engine/internal/signature/cades"
	"signer-engine/internal/signature/icpbrasil"
	"signer-engine/internal/tests/fixtures"
	"signer-engine/internal/tests/utils"
)

func TestPKCS12CAdESRejectsInvalidSigningCertificate(t *testing.T) {
	tests := []struct {
		name       string
		option     fixtures.ChainOption
		wantErrSub string
	}{
		{
			name:       "expired leaf",
			option:     fixtures.WithExpiredLeaf(),
			wantErrSub: "certificate has expired",
		},
		{
			name:       "leaf without digital signature key usage",
			option:     fixtures.WithoutDigitalSignatureKeyUsage(),
			wantErrSub: "certificate key usage does not allow digital signature",
		},
		{
			name:       "leaf without ICP-Brasil policy",
			option:     fixtures.WithoutICPBrasilPolicy(),
			wantErrSub: "certificate policies extension does not contain ICP-Brasil prefix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := fixtures.NewChain(t, tt.option)
			p12 := fixtures.NewPKCS12(t, chain, fixtures.DefaultPKCS12Password)
			service := signing.Service{
				PolicyResolver: policyResolver(t, chain.RootPEM),
			}

			_, err := service.Sign(signing.Request{
				Data:               []byte("signer-engine pkcs12 cades invalid certificate e2e"),
				CredentialProvider: signing.CredentialProviderPKCS12,
				PKCS12Data:         p12,
				PKCS12Pass:         fixtures.DefaultPKCS12Password,
				Format:             signing.FormatCades,
				Policy:             icpbrasil.PolicyNamePAADRBv24,
				Mode:               signing.ModeAttached,
			})
			utils.RequireErrorContains(t, err, tt.wantErrSub)
		})
	}
}

func TestCAdESCoSignRejectsDuplicateCertificate(t *testing.T) {
	chain := fixtures.NewChain(t)
	p12 := fixtures.NewPKCS12(t, chain, fixtures.DefaultPKCS12Password)
	content := []byte("co-sign duplicate certificate rejection e2e")
	service := newPolicyService(t, chain, defaultSigningTime)

	for _, mode := range []signing.Mode{signing.ModeAttached, signing.ModeDetached} {
		t.Run(string(mode), func(t *testing.T) {
			first, err := service.Sign(signing.Request{
				Operation:          signing.OperationSign,
				Data:               content,
				CredentialProvider: signing.CredentialProviderPKCS12,
				PKCS12Data:         p12,
				PKCS12Pass:         fixtures.DefaultPKCS12Password,
				Format:             signing.FormatCades,
				Policy:             icpbrasil.PolicyNamePAADRBv24,
				Mode:               mode,
			})
			if err != nil {
				t.Fatalf("first Sign failed: %v", err)
			}

			var coSignData []byte
			var existingSig []byte
			if mode == signing.ModeAttached {
				coSignData = first.Signature
			} else {
				coSignData = content
				existingSig = first.Signature
			}

			_, err = service.Sign(signing.Request{
				Operation:          signing.OperationCoSign,
				Data:               coSignData,
				ExistingSignature:  existingSig,
				CredentialProvider: signing.CredentialProviderPKCS12,
				PKCS12Data:         p12,
				PKCS12Pass:         fixtures.DefaultPKCS12Password,
				Format:             signing.FormatCades,
				Policy:             icpbrasil.PolicyNamePAADRBv24,
				Mode:               mode,
			})
			utils.RequireErrorContains(t, err, "certificate already present in signature")
		})
	}
}

func TestPKCS12CAdESPAADRTv24RequiresTimeStampProvider(t *testing.T) {
	chain := fixtures.NewChain(t)
	p12 := fixtures.NewPKCS12(t, chain, fixtures.DefaultPKCS12Password)
	service := signing.Service{
		PolicyResolver: policyResolver(t, chain.RootPEM),
	}

	_, err := service.Sign(signing.Request{
		Data:               []byte("signer-engine pkcs12 cades PA_AD_RT_v2_4 missing tsa e2e"),
		CredentialProvider: signing.CredentialProviderPKCS12,
		PKCS12Data:         p12,
		PKCS12Pass:         fixtures.DefaultPKCS12Password,
		Format:             signing.FormatCades,
		Policy:             icpbrasil.PolicyNamePAADRTv24,
		Mode:               signing.ModeAttached,
	})
	utils.RequireErrorContains(t, err, "time stamp provider is required")
}

func TestPKCS12CAdESValidationPoliciesRequireDependencies(t *testing.T) {
	chain := fixtures.NewChain(t)
	p12 := fixtures.NewPKCS12(t, chain, fixtures.DefaultPKCS12Password)

	tests := []struct {
		name                   string
		policy                 cades.PolicyName
		timeStampProvider      bool
		trustMaterialExtractor bool
		wantErrSub             string
	}{
		{
			name:                   "AD-RV without timestamp provider",
			policy:                 icpbrasil.PolicyNamePAADRVv24,
			timeStampProvider:      false,
			trustMaterialExtractor: true,
			wantErrSub:             "time stamp provider is required",
		},
		{
			name:                   "AD-RV without trust material extractor",
			policy:                 icpbrasil.PolicyNamePAADRVv24,
			timeStampProvider:      true,
			trustMaterialExtractor: false,
			wantErrSub:             "trust material extractor is required",
		},
		{
			name:                   "AD-RC without trust material extractor",
			policy:                 icpbrasil.PolicyNamePAADRCv24,
			timeStampProvider:      true,
			trustMaterialExtractor: false,
			wantErrSub:             "trust material extractor is required",
		},
		{
			name:                   "AD-RA without trust material extractor",
			policy:                 icpbrasil.PolicyNamePAADRAv25,
			timeStampProvider:      true,
			trustMaterialExtractor: false,
			wantErrSub:             "trust material extractor is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := signing.Service{
				PolicyResolver: policyResolver(t, chain.RootPEM),
			}
			if tt.timeStampProvider {
				service.TimeStampProvider = fixtures.NewTimeStampProvider(t)
			}
			if tt.trustMaterialExtractor {
				service.TrustMaterialExtractor = fixtures.NewTrustMaterialExtractor(t, chain)
			}

			_, err := service.Sign(signing.Request{
				Data:               []byte("signer-engine pkcs12 cades missing dependency e2e"),
				CredentialProvider: signing.CredentialProviderPKCS12,
				PKCS12Data:         p12,
				PKCS12Pass:         fixtures.DefaultPKCS12Password,
				Format:             signing.FormatCades,
				Policy:             tt.policy,
				Mode:               signing.ModeAttached,
			})
			utils.RequireErrorContains(t, err, tt.wantErrSub)
		})
	}
}
