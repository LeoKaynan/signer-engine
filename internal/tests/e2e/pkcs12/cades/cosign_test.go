package cades_test

import (
	"crypto/x509"
	"math/big"
	"testing"

	"signer-engine/internal/app/signing"
	"signer-engine/internal/signature/cades"
	"signer-engine/internal/signature/cms"
	"signer-engine/internal/signature/icpbrasil"
	"signer-engine/internal/tests/fixtures"
	"signer-engine/internal/tests/utils"
)

func TestCAdESCoSign(t *testing.T) {
	chain1 := fixtures.NewChain(t)
	chain2 := fixtures.NewChain(t, fixtures.WithLeafSerialNumber(big.NewInt(100)))

	p12First := fixtures.NewPKCS12(t, chain1, fixtures.DefaultPKCS12Password)
	p12Second := fixtures.NewPKCS12(t, chain2, fixtures.DefaultPKCS12Password)

	content := []byte("cades co-sign e2e test content")
	signingTime := defaultSigningTime
	policyInfo := requirePolicyInfo(t, icpbrasil.PolicyNamePAADRBv24)

	service1 := newPolicyService(t, chain1, signingTime)
	service2 := newPolicyService(t, chain2, signingTime)

	combinedTrust := utils.OpenSSLTrustStore{
		RootsPEM:         append(chain1.RootPEM, chain2.RootPEM...),
		IntermediatesPEM: append(chain1.IntermediatePEM, chain2.IntermediatePEM...),
	}

	for _, mode := range []signing.Mode{signing.ModeAttached, signing.ModeDetached} {
		t.Run(string(mode), func(t *testing.T) {
			firstResp, err := service1.Sign(signing.Request{
				Operation:          signing.OperationSign,
				Data:               content,
				CredentialProvider: signing.CredentialProviderPKCS12,
				PKCS12Data:         p12First,
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
				coSignData = firstResp.Signature
			} else {
				coSignData = content
				existingSig = firstResp.Signature
			}

			coSignResp, err := service2.Sign(signing.Request{
				Operation:          signing.OperationCoSign,
				Data:               coSignData,
				ExistingSignature:  existingSig,
				CredentialProvider: signing.CredentialProviderPKCS12,
				PKCS12Data:         p12Second,
				PKCS12Pass:         fixtures.DefaultPKCS12Password,
				Format:             signing.FormatCades,
				Policy:             icpbrasil.PolicyNamePAADRBv24,
				Mode:               mode,
			})
			if err != nil {
				t.Fatalf("CoSign failed: %v", err)
			}

			signedData := utils.ParseCAdES(t, coSignResp.Signature)

			utils.RequireSignerInfoCount(t, signedData, 2)

			utils.AssertContentMode(t, signedData, content, mode == signing.ModeDetached)

			if len(signedData.DigestAlgorithms) != 1 {
				t.Fatalf("expected 1 digest algorithm entry, got %d", len(signedData.DigestAlgorithms))
			}

			// Both signers must have correct messageDigest and policy — order is not guaranteed.
			leafCerts := []*x509.Certificate{chain1.Leaf, chain2.Leaf}
			for i, si := range signedData.SignerInfos {
				utils.AssertMessageDigest(t, utils.RequireSignedAttr(t, si, cms.OIDMessageDigest), content)
				utils.AssertSignaturePolicyIdentifier(
					t,
					utils.RequireSignedAttr(t, si, cades.OIDSignaturePolicyID),
					policyInfo.OID, policyInfo.Hash, policyInfo.URI,
				)
				utils.AssertSigningCertificateV2(t, utils.RequireSignedAttr(t, si, cades.OIDSigningCertificateV2), leafCerts[i])
			}

			utils.AssertSignedDataCertificates(t, signedData,
				chain1.Leaf, chain1.Intermediate,
				chain2.Leaf, chain2.Intermediate,
			)

			utils.VerifyCAdESWithOpenSSL(t, coSignResp.Signature, content, mode, combinedTrust)
		})
	}
}

func TestCAdESCoSignWithArchiveTimestampRenewal(t *testing.T) {
	chain1 := fixtures.NewChain(t)
	chain2 := fixtures.NewChain(t, fixtures.WithLeafSerialNumber(big.NewInt(200)))

	p12First := fixtures.NewPKCS12(t, chain1, fixtures.DefaultPKCS12Password)
	p12Second := fixtures.NewPKCS12(t, chain2, fixtures.DefaultPKCS12Password)

	content := []byte("cades co-sign archive timestamp renewal e2e")
	signingTime := defaultSigningTime

	service1 := newValidationPolicyService(t, chain1, signingTime)
	service2 := newValidationPolicyService(t, chain2, signingTime)

	combinedTrust := utils.OpenSSLTrustStore{
		RootsPEM:         append(chain1.RootPEM, chain2.RootPEM...),
		IntermediatesPEM: append(chain1.IntermediatePEM, chain2.IntermediatePEM...),
	}

	for _, mode := range []signing.Mode{signing.ModeAttached, signing.ModeDetached} {
		t.Run(string(mode), func(t *testing.T) {
			firstResp, err := service1.Sign(signing.Request{
				Operation:          signing.OperationSign,
				Data:               content,
				CredentialProvider: signing.CredentialProviderPKCS12,
				PKCS12Data:         p12First,
				PKCS12Pass:         fixtures.DefaultPKCS12Password,
				Format:             signing.FormatCades,
				Policy:             icpbrasil.PolicyNamePAADRAv25,
				Mode:               mode,
			})
			if err != nil {
				t.Fatalf("first Sign failed: %v", err)
			}

			var coSignData []byte
			var existingSig []byte
			if mode == signing.ModeAttached {
				coSignData = firstResp.Signature
			} else {
				coSignData = content
				existingSig = firstResp.Signature
			}

			coSignResp, err := service2.Sign(signing.Request{
				Operation:          signing.OperationCoSign,
				Data:               coSignData,
				ExistingSignature:  existingSig,
				CredentialProvider: signing.CredentialProviderPKCS12,
				PKCS12Data:         p12Second,
				PKCS12Pass:         fixtures.DefaultPKCS12Password,
				Format:             signing.FormatCades,
				Policy:             icpbrasil.PolicyNamePAADRAv25,
				Mode:               mode,
			})
			if err != nil {
				t.Fatalf("CoSign with AD-RA failed: %v", err)
			}

			signedData := utils.ParseCAdES(t, coSignResp.Signature)
			utils.RequireSignerInfoCount(t, signedData, 2)
			utils.AssertContentMode(t, signedData, content, mode == signing.ModeDetached)

			// Both signers must have ATSv2 renewed over the merged certificate set.
			for i, si := range signedData.SignerInfos {
				if _, ok := utils.FindUnsignedAttr(si, cades.OIDArchiveTimeStampV2); !ok {
					t.Fatalf("signer %d is missing ArchiveTimeStampV2", i)
				}
			}

			// All four certificates must be present (leaf+intermediate for each chain).
			utils.AssertSignedDataCertificates(t, signedData,
				chain1.Leaf, chain1.Intermediate,
				chain2.Leaf, chain2.Intermediate,
			)

			utils.VerifyCAdESWithOpenSSL(t, coSignResp.Signature, content, mode, combinedTrust)
		})
	}
}

func TestCAdESCoSignThreeSigners(t *testing.T) {
	chain1 := fixtures.NewChain(t)
	chain2 := fixtures.NewChain(t, fixtures.WithLeafSerialNumber(big.NewInt(300)))
	chain3 := fixtures.NewChain(t, fixtures.WithLeafSerialNumber(big.NewInt(301)))

	p12First := fixtures.NewPKCS12(t, chain1, fixtures.DefaultPKCS12Password)
	p12Second := fixtures.NewPKCS12(t, chain2, fixtures.DefaultPKCS12Password)
	p12Third := fixtures.NewPKCS12(t, chain3, fixtures.DefaultPKCS12Password)

	content := []byte("cades three-signer co-sign e2e")
	signingTime := defaultSigningTime
	policyInfo := requirePolicyInfo(t, icpbrasil.PolicyNamePAADRBv24)

	service1 := newPolicyService(t, chain1, signingTime)
	service2 := newPolicyService(t, chain2, signingTime)
	service3 := newPolicyService(t, chain3, signingTime)

	combinedTrust := utils.OpenSSLTrustStore{
		RootsPEM:         append(append(chain1.RootPEM, chain2.RootPEM...), chain3.RootPEM...),
		IntermediatesPEM: append(append(chain1.IntermediatePEM, chain2.IntermediatePEM...), chain3.IntermediatePEM...),
	}

	for _, mode := range []signing.Mode{signing.ModeAttached, signing.ModeDetached} {
		t.Run(string(mode), func(t *testing.T) {
			firstResp, err := service1.Sign(signing.Request{
				Operation:          signing.OperationSign,
				Data:               content,
				CredentialProvider: signing.CredentialProviderPKCS12,
				PKCS12Data:         p12First,
				PKCS12Pass:         fixtures.DefaultPKCS12Password,
				Format:             signing.FormatCades,
				Policy:             icpbrasil.PolicyNamePAADRBv24,
				Mode:               mode,
			})
			if err != nil {
				t.Fatalf("first Sign failed: %v", err)
			}

			coSignReq := func(sig []byte, p12 []byte) signing.Request {
				req := signing.Request{
					Operation:          signing.OperationCoSign,
					CredentialProvider: signing.CredentialProviderPKCS12,
					PKCS12Data:         p12,
					PKCS12Pass:         fixtures.DefaultPKCS12Password,
					Format:             signing.FormatCades,
					Policy:             icpbrasil.PolicyNamePAADRBv24,
					Mode:               mode,
				}
				if mode == signing.ModeAttached {
					req.Data = sig
				} else {
					req.Data = content
					req.ExistingSignature = sig
				}
				return req
			}

			secondResp, err := service2.Sign(coSignReq(firstResp.Signature, p12Second))
			if err != nil {
				t.Fatalf("second CoSign failed: %v", err)
			}

			thirdResp, err := service3.Sign(coSignReq(secondResp.Signature, p12Third))
			if err != nil {
				t.Fatalf("third CoSign failed: %v", err)
			}

			signedData := utils.ParseCAdES(t, thirdResp.Signature)
			utils.RequireSignerInfoCount(t, signedData, 3)
			utils.AssertContentMode(t, signedData, content, mode == signing.ModeDetached)

			leafCerts := []*x509.Certificate{chain1.Leaf, chain2.Leaf, chain3.Leaf}
			for i, si := range signedData.SignerInfos {
				utils.AssertMessageDigest(t, utils.RequireSignedAttr(t, si, cms.OIDMessageDigest), content)
				utils.AssertSignaturePolicyIdentifier(
					t,
					utils.RequireSignedAttr(t, si, cades.OIDSignaturePolicyID),
					policyInfo.OID, policyInfo.Hash, policyInfo.URI,
				)
				utils.AssertSigningCertificateV2(t, utils.RequireSignedAttr(t, si, cades.OIDSigningCertificateV2), leafCerts[i])
			}

			utils.AssertSignedDataCertificates(t, signedData,
				chain1.Leaf, chain1.Intermediate,
				chain2.Leaf, chain2.Intermediate,
				chain3.Leaf, chain3.Intermediate,
			)

			utils.VerifyCAdESWithOpenSSL(t, thirdResp.Signature, content, mode, combinedTrust)
		})
	}
}

func TestCAdESCoSignThreeSignersWithArchiveTimestampRenewal(t *testing.T) {
	chain1 := fixtures.NewChain(t)
	chain2 := fixtures.NewChain(t, fixtures.WithLeafSerialNumber(big.NewInt(400)))
	chain3 := fixtures.NewChain(t, fixtures.WithLeafSerialNumber(big.NewInt(401)))

	p12First := fixtures.NewPKCS12(t, chain1, fixtures.DefaultPKCS12Password)
	p12Second := fixtures.NewPKCS12(t, chain2, fixtures.DefaultPKCS12Password)
	p12Third := fixtures.NewPKCS12(t, chain3, fixtures.DefaultPKCS12Password)

	content := []byte("cades three-signer archive timestamp renewal e2e")
	signingTime := defaultSigningTime

	service1 := newValidationPolicyService(t, chain1, signingTime)
	service2 := newValidationPolicyService(t, chain2, signingTime)
	service3 := newValidationPolicyService(t, chain3, signingTime)

	combinedTrust := utils.OpenSSLTrustStore{
		RootsPEM:         append(append(chain1.RootPEM, chain2.RootPEM...), chain3.RootPEM...),
		IntermediatesPEM: append(append(chain1.IntermediatePEM, chain2.IntermediatePEM...), chain3.IntermediatePEM...),
	}

	for _, mode := range []signing.Mode{signing.ModeAttached, signing.ModeDetached} {
		t.Run(string(mode), func(t *testing.T) {
			firstResp, err := service1.Sign(signing.Request{
				Operation:          signing.OperationSign,
				Data:               content,
				CredentialProvider: signing.CredentialProviderPKCS12,
				PKCS12Data:         p12First,
				PKCS12Pass:         fixtures.DefaultPKCS12Password,
				Format:             signing.FormatCades,
				Policy:             icpbrasil.PolicyNamePAADRAv25,
				Mode:               mode,
			})
			if err != nil {
				t.Fatalf("first Sign failed: %v", err)
			}

			coSignReq := func(sig []byte, p12 []byte) signing.Request {
				req := signing.Request{
					Operation:          signing.OperationCoSign,
					CredentialProvider: signing.CredentialProviderPKCS12,
					PKCS12Data:         p12,
					PKCS12Pass:         fixtures.DefaultPKCS12Password,
					Format:             signing.FormatCades,
					Policy:             icpbrasil.PolicyNamePAADRAv25,
					Mode:               mode,
				}
				if mode == signing.ModeAttached {
					req.Data = sig
				} else {
					req.Data = content
					req.ExistingSignature = sig
				}
				return req
			}

			secondResp, err := service2.Sign(coSignReq(firstResp.Signature, p12Second))
			if err != nil {
				t.Fatalf("second CoSign with AD-RA failed: %v", err)
			}

			thirdResp, err := service3.Sign(coSignReq(secondResp.Signature, p12Third))
			if err != nil {
				t.Fatalf("third CoSign with AD-RA failed: %v", err)
			}

			signedData := utils.ParseCAdES(t, thirdResp.Signature)
			utils.RequireSignerInfoCount(t, signedData, 3)
			utils.AssertContentMode(t, signedData, content, mode == signing.ModeDetached)

			// All three signers must have ATSv2 renewed over the full merged certificate set.
			for i, si := range signedData.SignerInfos {
				if _, ok := utils.FindUnsignedAttr(si, cades.OIDArchiveTimeStampV2); !ok {
					t.Fatalf("signer %d is missing ArchiveTimeStampV2", i)
				}
			}

			// All six certificates must be present (leaf+intermediate for each chain).
			utils.AssertSignedDataCertificates(t, signedData,
				chain1.Leaf, chain1.Intermediate,
				chain2.Leaf, chain2.Intermediate,
				chain3.Leaf, chain3.Intermediate,
			)

			utils.VerifyCAdESWithOpenSSL(t, thirdResp.Signature, content, mode, combinedTrust)
		})
	}
}
