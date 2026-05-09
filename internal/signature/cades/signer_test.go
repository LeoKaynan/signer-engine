package cades_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"signer-engine/internal/signature/cades"
	"signer-engine/internal/signature/cms"
	"signer-engine/internal/testutil/certfixture"
	"signer-engine/internal/testutil/crlfixture"
	"signer-engine/internal/testutil/policyfixture"
	"signer-engine/internal/tsa"
	"signer-engine/internal/validation"
)

func TestSigner_Sign(t *testing.T) {
	credential := certfixture.NewCredential(t)

	cadesSigner := cades.Signer{
		Credential: credential,
		HashAlg:    crypto.SHA256,
		Detached:   false,
	}

	content := []byte("Hello, CAdES!")

	sigDER, err := cadesSigner.Sign(content)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	tmp := t.TempDir()
	sigPath := filepath.Join(tmp, "signature.p7s")
	dataPath := filepath.Join(tmp, "data.bin")

	if err := os.WriteFile(sigPath, sigDER, 0o644); err != nil {
		t.Fatalf("write sig: %v", err)
	}
	if err := os.WriteFile(dataPath, content, 0o644); err != nil {
		t.Fatalf("write data: %v", err)
	}

	cmd := exec.Command("openssl", "cms", "-verify", "-noverify",
		"-inform", "DER",
		"-in", sigPath,
		"-content", dataPath,
		"-out", os.DevNull,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl cms -verify failed: %v\noutput: %s", err, out)
	}

	signingTimeOIDDER, err := asn1.Marshal(cms.OIDSigningTime)
	if err != nil {
		t.Fatalf("marshal OID: %v", err)
	}
	if !bytes.Contains(sigDER, signingTimeOIDDER) {
		t.Error("signing-time OID not present in signature")
	}
}

type fakeTimeStampProvider struct {
	inputs  [][]byte
	hashAlg crypto.Hash
	certs   []*x509.Certificate
}

func (p *fakeTimeStampProvider) Stamp(ctx context.Context, input []byte, hashAlg crypto.Hash) (*tsa.TimestampToken, error) {
	p.inputs = append(p.inputs, append([]byte(nil), input...))
	p.hashAlg = hashAlg

	if len(p.certs) > 0 {
		tokenDER, err := timestampTokenWithCertificates(p.certs)
		if err != nil {
			return nil, err
		}
		return &tsa.TimestampToken{TokenDER: tokenDER}, nil
	}

	tokenDER, err := asn1.Marshal(struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}{
		ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		Content: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSequence,
			IsCompound: true,
			Bytes:      []byte{0x05, 0x00},
		},
	})
	if err != nil {
		return nil, err
	}

	return &tsa.TimestampToken{TokenDER: tokenDER}, nil
}

func timestampTokenWithCertificates(certs []*x509.Certificate) ([]byte, error) {
	certificates := make([]asn1.RawValue, 0, len(certs))
	for _, cert := range certs {
		certificates = append(certificates, asn1.RawValue{FullBytes: cert.Raw})
	}

	signedDataBytes, err := asn1.Marshal(cms.SignedData{
		Version: 1,
		DigestAlgorithms: []cms.AlgorithmIdentifier{
			{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}},
		},
		EncapContentInfo: cms.EncapsulatedContentInfo{
			EContentType: cms.OIDData,
		},
		Certificates: certificates,
		SignerInfos:  timestampSignerInfos(certs),
	})
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(cms.ContentInfo{
		ContentType: cms.OIDSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      signedDataBytes,
		},
	})
}

func timestampSignerInfos(certs []*x509.Certificate) []cms.SignerInfo {
	if len(certs) == 0 {
		return nil
	}

	return []cms.SignerInfo{
		{
			Version: 1,
			SID: cms.IssuerAndSerialNumber{
				Issuer: asn1.RawValue{
					FullBytes: certs[0].RawIssuer,
				},
				SerialNumber: certs[0].SerialNumber,
			},
			DigestAlgorithm: cms.AlgorithmIdentifier{
				Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1},
			},
			SignatureAlgorithm: cms.AlgorithmIdentifier{
				Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1},
			},
			Signature: []byte{0x01},
		},
	}
}

func TestSigner_SignWithSignatureTimeStamp(t *testing.T) {
	credential := certfixture.NewCredential(t)
	policy := policyfixture.Policy{
		UnsignedAttrs: []cades.AttributeName{
			cades.SignatureTimeStampTokenAttr,
		},
	}
	timeStampProvider := &fakeTimeStampProvider{}

	cadesSigner := cades.Signer{
		Credential:        credential,
		HashAlg:           crypto.SHA256,
		Detached:          false,
		Policy:            policy,
		TimeStampProvider: timeStampProvider,
	}

	sigDER, err := cadesSigner.Sign([]byte("Hello, CAdES AD-RT!"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(timeStampProvider.inputs) != 1 || len(timeStampProvider.inputs[0]) == 0 {
		t.Fatal("expected timestamp provider to receive signature bytes")
	}
	if timeStampProvider.hashAlg != crypto.SHA256 {
		t.Fatalf("unexpected timestamp hash alg: %v", timeStampProvider.hashAlg)
	}

	oidDER, err := asn1.Marshal(cades.OIDSignatureTimeStampToken)
	if err != nil {
		t.Fatalf("marshal OID: %v", err)
	}
	if !bytes.Contains(sigDER, oidDER) {
		t.Fatal("signature timestamp token OID not present in signature")
	}
}

func TestSigner_SignWithSignatureTimeStampRequiresProvider(t *testing.T) {
	credential := certfixture.NewCredential(t)
	policy := policyfixture.Policy{
		UnsignedAttrs: []cades.AttributeName{
			cades.SignatureTimeStampTokenAttr,
		},
	}

	cadesSigner := cades.Signer{
		Credential: credential,
		HashAlg:    crypto.SHA256,
		Detached:   false,
		Policy:     policy,
	}

	_, err := cadesSigner.Sign([]byte("Hello, CAdES AD-RT!"))
	if err == nil {
		t.Fatal("expected missing timestamp provider error")
	}
	if !strings.Contains(err.Error(), "time stamp provider is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

type fakeTrustMaterialExtractor struct {
	calls  int
	cert   *x509.Certificate
	chain  []*x509.Certificate
	certs  []*x509.Certificate
	chains [][]*x509.Certificate
	crls   []*x509.RevocationList
	tsa    *validation.TrustMaterial
}

func (p *fakeTrustMaterialExtractor) FromCertificate(ctx context.Context, cert *x509.Certificate, chain []*x509.Certificate) (*validation.TrustMaterial, error) {
	p.calls++
	p.cert = cert
	p.chain = append([]*x509.Certificate(nil), chain...)
	p.certs = append(p.certs, cert)
	p.chains = append(p.chains, append([]*x509.Certificate(nil), chain...))

	return &validation.TrustMaterial{
		Leaf:  cert,
		Chain: append([]*x509.Certificate(nil), chain...),
		CRLs:  append([]*x509.RevocationList(nil), p.crls...),
	}, nil
}

func (p *fakeTrustMaterialExtractor) FromTimestampToken(ctx context.Context, tokenDER []byte) (*validation.TrustMaterial, error) {
	p.calls++
	if p.tsa == nil {
		return nil, nil
	}

	chain := append([]*x509.Certificate(nil), p.tsa.Chain...)
	p.certs = append(p.certs, p.tsa.Leaf)
	p.chains = append(p.chains, chain)

	return &validation.TrustMaterial{
		Leaf:  p.tsa.Leaf,
		Chain: chain,
		CRLs:  append([]*x509.RevocationList(nil), p.tsa.CRLs...),
	}, nil
}

func TestSigner_SignWithValidationRefs(t *testing.T) {
	credential := certfixture.NewCredential(t)
	revocationFixture := crlfixture.New(t)
	policy := policyfixture.Policy{
		UnsignedAttrs: []cades.AttributeName{
			cades.CertificateRefsAttr,
			cades.RevocationRefsAttr,
		},
	}
	extractor := &fakeTrustMaterialExtractor{
		crls: []*x509.RevocationList{revocationFixture.LeafCRL},
	}

	cadesSigner := cades.Signer{
		Credential:             credential,
		HashAlg:                crypto.SHA256,
		Detached:               false,
		Policy:                 policy,
		TrustMaterialExtractor: extractor,
	}

	sigDER, err := cadesSigner.Sign([]byte("Hello, CAdES AD-RV!"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if extractor.calls != 1 {
		t.Fatalf("expected extractor to be called once, got %d", extractor.calls)
	}
	if extractor.cert == nil {
		t.Fatal("expected extractor to receive signer certificate")
	}
	if len(extractor.chain) == 0 {
		t.Fatal("expected extractor to receive certificate chain")
	}

	certificateRefsOIDDER, err := asn1.Marshal(cades.OIDCertificateRefs)
	if err != nil {
		t.Fatalf("marshal OID: %v", err)
	}
	if !bytes.Contains(sigDER, certificateRefsOIDDER) {
		t.Fatal("certificate refs OID not present in signature")
	}

	revocationRefsOIDDER, err := asn1.Marshal(cades.OIDRevocationRefs)
	if err != nil {
		t.Fatalf("marshal OID: %v", err)
	}
	if !bytes.Contains(sigDER, revocationRefsOIDDER) {
		t.Fatal("revocation refs OID not present in signature")
	}
}

func TestSigner_SignWithValidationRefsRequiresProvider(t *testing.T) {
	credential := certfixture.NewCredential(t)
	policy := policyfixture.Policy{
		UnsignedAttrs: []cades.AttributeName{
			cades.CertificateRefsAttr,
		},
	}

	cadesSigner := cades.Signer{
		Credential: credential,
		HashAlg:    crypto.SHA256,
		Detached:   false,
		Policy:     policy,
	}

	_, err := cadesSigner.Sign([]byte("Hello, CAdES AD-RV!"))
	if err == nil {
		t.Fatal("expected missing validation provider error")
	}
	if !strings.Contains(err.Error(), "trust material extractor is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSigner_SignWithEscTimeStamp(t *testing.T) {
	credential := certfixture.NewCredential(t)
	timestampCredential := certfixture.NewCredential(t)
	revocationFixture := crlfixture.New(t)
	policy := policyfixture.Policy{
		UnsignedAttrs: []cades.AttributeName{
			cades.SignatureTimeStampTokenAttr,
			cades.CertificateRefsAttr,
			cades.RevocationRefsAttr,
			cades.EscTimeStampAttr,
		},
	}
	timeStampProvider := &fakeTimeStampProvider{
		certs: []*x509.Certificate{timestampCredential.Certificate()},
	}
	extractor := &fakeTrustMaterialExtractor{
		crls: []*x509.RevocationList{revocationFixture.LeafCRL},
		tsa: &validation.TrustMaterial{
			Leaf: timestampCredential.Certificate(),
			CRLs: []*x509.RevocationList{revocationFixture.LeafCRL},
		},
	}

	cadesSigner := cades.Signer{
		Credential:             credential,
		HashAlg:                crypto.SHA256,
		Detached:               false,
		Policy:                 policy,
		TimeStampProvider:      timeStampProvider,
		TrustMaterialExtractor: extractor,
	}

	sigDER, err := cadesSigner.Sign([]byte("Hello, CAdES AD-RV!"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(timeStampProvider.inputs) != 2 {
		t.Fatalf("expected timestamp provider to be called twice, got %d", len(timeStampProvider.inputs))
	}
	if len(timeStampProvider.inputs[0]) == 0 {
		t.Fatal("expected first timestamp input to be signature bytes")
	}
	if len(timeStampProvider.inputs[1]) <= len(timeStampProvider.inputs[0]) {
		t.Fatal("expected esc timestamp input to include signature and previous unsigned attributes")
	}
	if extractor.calls != 3 {
		t.Fatalf("expected extractor to be called three times, got %d", extractor.calls)
	}
	externalChain := extractor.chains[1]
	if len(externalChain) != len(credential.Chain())+1 {
		t.Fatalf("expected validation chain to include timestamp certificate, got %d", len(externalChain))
	}
	if !bytes.Equal(externalChain[len(externalChain)-1].Raw, timestampCredential.Certificate().Raw) {
		t.Fatal("expected timestamp certificate to be appended to validation chain")
	}

	oidDER, err := asn1.Marshal(cades.OIDEscTimeStamp)
	if err != nil {
		t.Fatalf("marshal OID: %v", err)
	}
	if !bytes.Contains(sigDER, oidDER) {
		t.Fatal("esc timestamp OID not present in signature")
	}

	certificateRefsOIDDER, err := asn1.Marshal(cades.OIDCertificateRefs)
	if err != nil {
		t.Fatalf("marshal certificate refs OID: %v", err)
	}
	if count := bytes.Count(sigDER, certificateRefsOIDDER); count != 3 {
		t.Fatalf("expected certificate refs on outer signer and both timestamp tokens, got %d", count)
	}

	revocationRefsOIDDER, err := asn1.Marshal(cades.OIDRevocationRefs)
	if err != nil {
		t.Fatalf("marshal revocation refs OID: %v", err)
	}
	if count := bytes.Count(sigDER, revocationRefsOIDDER); count != 3 {
		t.Fatalf("expected revocation refs on outer signer and both timestamp tokens, got %d", count)
	}
}

func TestSigner_SignWithArchivalValuesWithoutRefsIncludesTimestampCertificate(t *testing.T) {
	credential := certfixture.NewCredential(t)
	timestampCredential := certfixture.NewCredential(t)
	revocationFixture := crlfixture.New(t)
	policy := policyfixture.Policy{
		UnsignedAttrs: []cades.AttributeName{
			cades.SignatureTimeStampTokenAttr,
			cades.CertValuesAttr,
			cades.RevocationValuesAttr,
		},
	}
	timeStampProvider := &fakeTimeStampProvider{
		certs: []*x509.Certificate{timestampCredential.Certificate()},
	}
	extractor := &fakeTrustMaterialExtractor{
		crls: []*x509.RevocationList{revocationFixture.LeafCRL},
		tsa: &validation.TrustMaterial{
			Leaf: timestampCredential.Certificate(),
			CRLs: []*x509.RevocationList{revocationFixture.LeafCRL},
		},
	}

	signer := cades.Signer{
		Credential:             credential,
		HashAlg:                crypto.SHA256,
		Detached:               false,
		Policy:                 policy,
		TimeStampProvider:      timeStampProvider,
		TrustMaterialExtractor: extractor,
	}

	sigDER, err := signer.Sign([]byte("Hello, CAdES AD-RC values only!"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if extractor.calls != 2 {
		t.Fatalf("expected extractor to be called twice, got %d", extractor.calls)
	}
	if len(extractor.chains) < 2 {
		t.Fatalf("expected timestamp and signer material calls, got %d", len(extractor.chains))
	}
	signerChain := extractor.chains[1]
	if len(signerChain) != len(credential.Chain())+1 {
		t.Fatalf("expected signer chain to include timestamp certificate, got %d", len(signerChain))
	}
	if !bytes.Equal(signerChain[len(signerChain)-1].Raw, timestampCredential.Certificate().Raw) {
		t.Fatal("expected timestamp certificate to be appended to signer material chain")
	}

	certValuesOIDDER, err := asn1.Marshal(cades.OIDCertValues)
	if err != nil {
		t.Fatalf("marshal cert values OID: %v", err)
	}
	if count := bytes.Count(sigDER, certValuesOIDDER); count != 1 {
		t.Fatalf("expected cert values only on outer signer, got %d", count)
	}

	revocationValuesOIDDER, err := asn1.Marshal(cades.OIDRevocationValues)
	if err != nil {
		t.Fatalf("marshal revocation values OID: %v", err)
	}
	if count := bytes.Count(sigDER, revocationValuesOIDDER); count != 1 {
		t.Fatalf("expected revocation values only on outer signer, got %d", count)
	}
}

func TestSigner_SignWithArchivalValues(t *testing.T) {
	credential := certfixture.NewCredential(t)
	timestampCredential := certfixture.NewCredential(t)
	revocationFixture := crlfixture.New(t)
	policy := policyfixture.Policy{
		UnsignedAttrs: []cades.AttributeName{
			cades.SignatureTimeStampTokenAttr,
			cades.CertificateRefsAttr,
			cades.RevocationRefsAttr,
			cades.EscTimeStampAttr,
			cades.CertValuesAttr,
			cades.RevocationValuesAttr,
		},
	}
	timeStampProvider := &fakeTimeStampProvider{
		certs: []*x509.Certificate{timestampCredential.Certificate()},
	}
	extractor := &fakeTrustMaterialExtractor{
		crls: []*x509.RevocationList{revocationFixture.LeafCRL},
		tsa: &validation.TrustMaterial{
			Leaf: timestampCredential.Certificate(),
			CRLs: []*x509.RevocationList{revocationFixture.LeafCRL},
		},
	}

	cadesSigner := cades.Signer{
		Credential:             credential,
		HashAlg:                crypto.SHA256,
		Detached:               false,
		Policy:                 policy,
		TimeStampProvider:      timeStampProvider,
		TrustMaterialExtractor: extractor,
	}

	sigDER, err := cadesSigner.Sign([]byte("Hello, CAdES AD-RC!"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if extractor.calls != 3 {
		t.Fatalf("expected extractor to be called three times, got %d", extractor.calls)
	}

	certValuesOIDDER, err := asn1.Marshal(cades.OIDCertValues)
	if err != nil {
		t.Fatalf("marshal cert values OID: %v", err)
	}
	if count := bytes.Count(sigDER, certValuesOIDDER); count != 3 {
		t.Fatalf("expected cert values on outer signer and both timestamp tokens, got %d", count)
	}

	revocationValuesOIDDER, err := asn1.Marshal(cades.OIDRevocationValues)
	if err != nil {
		t.Fatalf("marshal revocation values OID: %v", err)
	}
	if count := bytes.Count(sigDER, revocationValuesOIDDER); count != 3 {
		t.Fatalf("expected revocation values on outer signer and both timestamp tokens, got %d", count)
	}
}

func TestSigner_SignWithArchiveTimeStampV2(t *testing.T) {
	credential := certfixture.NewCredential(t)
	timestampCredential := certfixture.NewCredential(t)
	revocationFixture := crlfixture.New(t)
	policy := policyfixture.Policy{
		UnsignedAttrs: []cades.AttributeName{
			cades.SignatureTimeStampTokenAttr,
			cades.CertificateRefsAttr,
			cades.RevocationRefsAttr,
			cades.EscTimeStampAttr,
			cades.CertValuesAttr,
			cades.RevocationValuesAttr,
			cades.ArchiveTimeStampV2Attr,
		},
	}
	timeStampProvider := &fakeTimeStampProvider{
		certs: []*x509.Certificate{timestampCredential.Certificate()},
	}
	extractor := &fakeTrustMaterialExtractor{
		crls: []*x509.RevocationList{revocationFixture.LeafCRL},
		tsa: &validation.TrustMaterial{
			Leaf: timestampCredential.Certificate(),
			CRLs: []*x509.RevocationList{revocationFixture.LeafCRL},
		},
	}

	cadesSigner := cades.Signer{
		Credential:             credential,
		HashAlg:                crypto.SHA256,
		Detached:               false,
		Policy:                 policy,
		TimeStampProvider:      timeStampProvider,
		TrustMaterialExtractor: extractor,
	}

	sigDER, err := cadesSigner.Sign([]byte("Hello, CAdES AD-RA!"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(timeStampProvider.inputs) != 3 {
		t.Fatalf("expected timestamp provider to be called three times, got %d", len(timeStampProvider.inputs))
	}
	if len(timeStampProvider.inputs[2]) <= len(timeStampProvider.inputs[1]) {
		t.Fatal("expected archive timestamp input to cover validation values and previous timestamps")
	}
	if extractor.calls != 4 {
		t.Fatalf("expected extractor to be called four times, got %d", extractor.calls)
	}

	archiveTimeStampOIDDER, err := asn1.Marshal(cades.OIDArchiveTimeStampV2)
	if err != nil {
		t.Fatalf("marshal archive timestamp OID: %v", err)
	}
	if !bytes.Contains(sigDER, archiveTimeStampOIDDER) {
		t.Fatal("archive timestamp v2 OID not present in signature")
	}

	certValuesOIDDER, err := asn1.Marshal(cades.OIDCertValues)
	if err != nil {
		t.Fatalf("marshal cert values OID: %v", err)
	}
	if count := bytes.Count(sigDER, certValuesOIDDER); count != 4 {
		t.Fatalf("expected cert values on outer signer and all timestamp tokens, got %d", count)
	}
}
