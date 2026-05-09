package cades_test

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"signer-engine/internal/app/signing"
	"signer-engine/internal/cryptoutil"
	"signer-engine/internal/signature/cades"
	"signer-engine/internal/signature/cms"
	"signer-engine/internal/signature/icpbrasil"
	"signer-engine/internal/tests/fixtures"
	"signer-engine/internal/tests/utils"
)

var defaultSigningTime = time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)

type policyService struct {
	Service                signing.Service
	TimeStampProvider      *fixtures.TimeStampProvider
	TrustMaterialExtractor *fixtures.TrustMaterialExtractor
}

func policyResolver(t testing.TB, rootsPEM []byte) func(cades.PolicyName) (cades.Policy, error) {
	t.Helper()

	return func(name cades.PolicyName) (cades.Policy, error) {
		return fixtures.NewICPBrasilPolicy(t, name, rootsPEM), nil
	}
}

func requirePolicyInfo(t testing.TB, name cades.PolicyName) icpbrasil.PolicyInfo {
	t.Helper()

	info, ok := icpbrasil.PolicyInfoByName(name)
	if !ok {
		t.Fatalf("%s policy info not found", name)
	}
	return info
}

func newPolicyService(t testing.TB, chain fixtures.Chain, signingTime time.Time) policyService {
	t.Helper()

	return policyService{
		Service: signing.Service{
			PolicyResolver: policyResolver(t, chain.RootPEM),
			Now: func() time.Time {
				return signingTime
			},
		},
	}
}

func (s policyService) Sign(request signing.Request) (signing.Response, error) {
	return s.Service.Sign(request)
}

func newTimeStampPolicyService(t testing.TB, chain fixtures.Chain, signingTime time.Time) policyService {
	t.Helper()

	service := newPolicyService(t, chain, signingTime)
	service.TimeStampProvider = fixtures.NewTimeStampProvider(t)
	service.Service.TimeStampProvider = service.TimeStampProvider
	return service
}

func newValidationPolicyService(t testing.TB, chain fixtures.Chain, signingTime time.Time) policyService {
	t.Helper()

	service := newTimeStampPolicyService(t, chain, signingTime)
	service.TrustMaterialExtractor = fixtures.NewTrustMaterialExtractor(t, chain)
	service.Service.TrustMaterialExtractor = service.TrustMaterialExtractor
	return service
}

func assertCommonCAdES(
	t testing.TB,
	signature []byte,
	content []byte,
	mode signing.Mode,
	chain fixtures.Chain,
	signingTime time.Time,
	policyInfo icpbrasil.PolicyInfo,
) cms.SignerInfo {
	t.Helper()

	signedData := utils.ParseCAdES(t, signature)
	utils.AssertContentMode(t, signedData, content, mode == signing.ModeDetached)
	signerInfo := utils.RequireSingleSignerInfo(t, signedData)
	utils.AssertSHA256DigestAlgorithms(t, signedData, signerInfo)
	utils.AssertSignedDataCertificates(t, signedData, chain.Leaf, chain.Intermediate)
	utils.AssertSignerInfoSID(t, signerInfo, chain.Leaf)
	utils.AssertContentType(t, utils.RequireSignedAttr(t, signerInfo, cms.OIDContentType), cms.OIDData)
	utils.AssertMessageDigest(t, utils.RequireSignedAttr(t, signerInfo, cms.OIDMessageDigest), content)
	utils.AssertSigningTime(t, utils.RequireSignedAttr(t, signerInfo, cms.OIDSigningTime), signingTime)
	utils.AssertSigningCertificateV2(
		t,
		utils.RequireSignedAttr(t, signerInfo, cades.OIDSigningCertificateV2),
		chain.Leaf,
	)
	utils.AssertSignaturePolicyIdentifier(
		t,
		utils.RequireSignedAttr(t, signerInfo, cades.OIDSignaturePolicyID),
		policyInfo.OID,
		policyInfo.Hash,
		policyInfo.URI,
	)

	return signerInfo
}

type unsignedAttrKind int

const (
	unsignedAttrUnset unsignedAttrKind = iota
	unsignedAttrASN1
	unsignedAttrTimestamp
)

type expectedUnsignedAttr struct {
	oid  asn1.ObjectIdentifier
	kind unsignedAttrKind
}

func assertUnsignedAttrs(t testing.TB, signerInfo cms.SignerInfo, attrs ...expectedUnsignedAttr) {
	t.Helper()

	oids := make([]asn1.ObjectIdentifier, 0, len(attrs))
	for _, attr := range attrs {
		oids = append(oids, attr.oid)
	}
	utils.RequireUnsignedAttrs(t, signerInfo, oids...)

	for _, expected := range attrs {
		attr := utils.RequireUnsignedAttr(t, signerInfo, expected.oid)
		switch expected.kind {
		case unsignedAttrTimestamp:
			utils.AssertTimestampTokenAttribute(t, attr)
		case unsignedAttrASN1:
			utils.AssertASN1AttributeValue(t, attr)
		default:
			t.Fatalf("unsupported unsigned attr kind: %d", expected.kind)
		}
	}
}

func timestampAttributeCount(policyInfo icpbrasil.PolicyInfo) int {
	var count int
	for _, attr := range policyInfo.RequiredUnsignedAttributes {
		switch attr {
		case cades.SignatureTimeStampTokenAttr, cades.EscTimeStampAttr, cades.ArchiveTimeStampV2Attr:
			count++
		}
	}
	return count
}

func assertTimeStampProviderCalls(
	t testing.TB,
	provider *fixtures.TimeStampProvider,
	count int,
	signature []byte,
) {
	t.Helper()

	if len(provider.Inputs) != count {
		t.Fatalf("expected timestamp provider to be called %d times, got %d", count, len(provider.Inputs))
	}
	if len(provider.HashAlgs) != count {
		t.Fatalf("expected %d timestamp hash alg entries, got %d", count, len(provider.HashAlgs))
	}
	for _, hashAlg := range provider.HashAlgs {
		if hashAlg != crypto.SHA256 {
			t.Fatalf("unexpected timestamp hash algorithm: got=%v want=%v", hashAlg, crypto.SHA256)
		}
	}
	if count == 0 {
		return
	}
	if !bytes.Equal(provider.Inputs[0], signature) {
		t.Fatal("expected first timestamp provider input to be the signer info signature")
	}
	// Validation and archive timestamps include previously built unsigned
	// attributes, so each subsequent input should grow.
	for i := 1; i < len(provider.Inputs); i++ {
		if len(provider.Inputs[i]) <= len(provider.Inputs[i-1]) {
			t.Fatalf("expected timestamp input %d to include previous validation material", i)
		}
	}
}

func assertTrustMaterialExtractorCalls(t testing.TB, extractor *fixtures.TrustMaterialExtractor, timestampCalls int) {
	t.Helper()

	if extractor.CertificateCalls != 1 {
		t.Fatalf("expected one signer trust material call, got %d", extractor.CertificateCalls)
	}
	if extractor.TimestampTokenCalls != timestampCalls {
		t.Fatalf("expected %d timestamp trust material calls, got %d", timestampCalls, extractor.TimestampTokenCalls)
	}
}

type e2eOtherHashAlgAndValue struct {
	HashAlgorithm cms.AlgorithmIdentifier
	HashValue     []byte
}

type e2eOtherCertID struct {
	OtherCertHash e2eOtherHashAlgAndValue
	IssuerSerial  struct {
		Issuer       []asn1.RawValue
		SerialNumber *big.Int
	} `asn1:"optional"`
}

type e2eCRLValidatedID struct {
	CRLHash e2eOtherHashAlgAndValue
}

type e2eCRLListID struct {
	CRLs []e2eCRLValidatedID
}

type e2eCRLOcspRef struct {
	CRLIDs e2eCRLListID `asn1:"explicit,tag:0,optional"`
}

type e2eRevocationValues struct {
	CRLVals []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

func assertValidationMaterialAttrs(t testing.TB, signerInfo cms.SignerInfo, chain fixtures.Chain, extractor *fixtures.TrustMaterialExtractor) {
	t.Helper()

	assertCertificateRefs(t, utils.RequireUnsignedAttr(t, signerInfo, cades.OIDCertificateRefs), chain.Intermediate)
	assertCertificateValues(t, utils.RequireUnsignedAttr(t, signerInfo, cades.OIDCertValues), chain.Intermediate)
	assertRevocationRefs(t, utils.RequireUnsignedAttr(t, signerInfo, cades.OIDRevocationRefs), extractor.SignerCRLs...)
	assertRevocationValues(t, utils.RequireUnsignedAttr(t, signerInfo, cades.OIDRevocationValues), extractor.SignerCRLs...)
}

func assertCertificateRefs(t testing.TB, attr cms.Attribute, certs ...*x509.Certificate) {
	t.Helper()

	var refs []e2eOtherCertID
	unmarshalAttrValue(t, attr, &refs)
	if len(refs) != len(certs) {
		t.Fatalf("expected %d certificate refs, got %d", len(certs), len(refs))
	}
	for i, cert := range certs {
		assertSHA256OtherHash(t, refs[i].OtherCertHash, cert.Raw)
		if len(refs[i].IssuerSerial.Issuer) != 1 {
			t.Fatalf("expected one certificate ref issuer, got %d", len(refs[i].IssuerSerial.Issuer))
		}
	}
}

func assertCertificateValues(t testing.TB, attr cms.Attribute, certs ...*x509.Certificate) {
	t.Helper()

	var values []asn1.RawValue
	unmarshalAttrValue(t, attr, &values)
	if len(values) != len(certs) {
		t.Fatalf("expected %d certificate values, got %d", len(certs), len(values))
	}
	for i, cert := range certs {
		if !bytes.Equal(values[i].FullBytes, cert.Raw) {
			t.Fatalf("unexpected certificate value %d", i)
		}
	}
}

func assertRevocationRefs(t testing.TB, attr cms.Attribute, crls ...*x509.RevocationList) {
	t.Helper()

	var refs []e2eCRLOcspRef
	unmarshalAttrValue(t, attr, &refs)
	if len(refs) != len(crls) {
		t.Fatalf("expected %d revocation refs, got %d", len(crls), len(refs))
	}
	for i, crl := range crls {
		if len(refs[i].CRLIDs.CRLs) != 1 {
			t.Fatalf("expected revocation ref %d to contain one CRL id, got %d", i, len(refs[i].CRLIDs.CRLs))
		}
		assertSHA256OtherHash(t, refs[i].CRLIDs.CRLs[0].CRLHash, crl.Raw)
	}
}

func assertRevocationValues(t testing.TB, attr cms.Attribute, crls ...*x509.RevocationList) {
	t.Helper()

	var values e2eRevocationValues
	unmarshalAttrValue(t, attr, &values)
	if len(values.CRLVals) != len(crls) {
		t.Fatalf("expected %d revocation values, got %d", len(crls), len(values.CRLVals))
	}
	for i, crl := range crls {
		if !bytes.Equal(values.CRLVals[i].FullBytes, crl.Raw) {
			t.Fatalf("unexpected revocation value %d", i)
		}
	}
}

func assertSHA256OtherHash(t testing.TB, got e2eOtherHashAlgAndValue, input []byte) {
	t.Helper()

	if !got.HashAlgorithm.Algorithm.Equal(cryptoutil.OIDSHA256) {
		t.Fatalf("unexpected hash algorithm: got=%s want=%s", got.HashAlgorithm.Algorithm, cryptoutil.OIDSHA256)
	}
	if len(got.HashAlgorithm.Parameters.FullBytes) != 0 {
		t.Fatal("expected SHA-256 algorithm identifier without parameters")
	}
	expected := sha256.Sum256(input)
	if !bytes.Equal(got.HashValue, expected[:]) {
		t.Fatalf("unexpected hash value: got=%x want=%x", got.HashValue, expected)
	}
}

func assertAdvancedTimestampInputs(
	t testing.TB,
	signature []byte,
	content []byte,
	mode signing.Mode,
	provider *fixtures.TimeStampProvider,
) {
	t.Helper()

	signedData := utils.ParseCAdES(t, signature)
	signerInfo := utils.RequireSingleSignerInfo(t, signedData)
	if len(provider.Inputs) != 3 {
		t.Fatalf("expected three timestamp inputs for AD-RA, got %d", len(provider.Inputs))
	}

	previousEscAttrs := []cms.Attribute{
		utils.RequireUnsignedAttr(t, signerInfo, cades.OIDSignatureTimeStampToken),
		utils.RequireUnsignedAttr(t, signerInfo, cades.OIDCertificateRefs),
		utils.RequireUnsignedAttr(t, signerInfo, cades.OIDRevocationRefs),
	}
	escInput, err := cades.EscTimeStampInput(signerInfo.Signature, previousEscAttrs)
	if err != nil {
		t.Fatalf("failed to rebuild esc timestamp input: %v", err)
	}
	if !bytes.Equal(provider.Inputs[1], escInput) {
		t.Fatal("esc timestamp input does not match signature plus previous unsigned attributes")
	}

	previousArchiveAttrs := append(previousEscAttrs,
		utils.RequireUnsignedAttr(t, signerInfo, cades.OIDEscTimeStamp),
		utils.RequireUnsignedAttr(t, signerInfo, cades.OIDCertValues),
		utils.RequireUnsignedAttr(t, signerInfo, cades.OIDRevocationValues),
	)
	archiveInput, err := cades.ArchiveTimeStampV2Input(cms.UnsignedAttributeContext{
		Signature:        signerInfo.Signature,
		HashAlg:          crypto.SHA256,
		Data:             content,
		Detached:         mode == signing.ModeDetached,
		EncapContentInfo: signedData.EncapContentInfo,
		Certificates:     signedData.Certificates,
		CRLs:             signedData.CRLs,
		SignerInfo:       signerInfo,
	}, previousArchiveAttrs)
	if err != nil {
		t.Fatalf("failed to rebuild archive timestamp input: %v", err)
	}
	if !bytes.Equal(provider.Inputs[2], archiveInput) {
		t.Fatal("archive timestamp input does not match signed data plus previous validation material")
	}
}

func unmarshalAttrValue(t testing.TB, attr cms.Attribute, dst any) {
	t.Helper()

	if len(attr.AttrValues) != 1 {
		t.Fatalf("expected one value for attr %s, got %d", attr.AttrType, len(attr.AttrValues))
	}
	if rest, err := asn1.Unmarshal(attr.AttrValues[0].FullBytes, dst); err != nil {
		t.Fatalf("failed to unmarshal attr %s: %v", attr.AttrType, err)
	} else if len(rest) != 0 {
		t.Fatalf("unexpected trailing attr %s data: %x", attr.AttrType, rest)
	}
}
