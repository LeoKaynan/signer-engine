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

type fakeValidationProvider struct {
	calls  int
	cert   *x509.Certificate
	chain  []*x509.Certificate
	certs  []*x509.Certificate
	chains [][]*x509.Certificate
}

func (p *fakeValidationProvider) BuildRefs(ctx context.Context, cert *x509.Certificate, chain []*x509.Certificate) (*validation.Refs, error) {
	p.calls++
	p.cert = cert
	p.chain = append([]*x509.Certificate(nil), chain...)
	p.certs = append(p.certs, cert)
	p.chains = append(p.chains, append([]*x509.Certificate(nil), chain...))

	certRefsDER, err := asn1.Marshal([]byte("certificate-refs"))
	if err != nil {
		return nil, err
	}

	revocationRefsDER, err := asn1.Marshal([]byte("revocation-refs"))
	if err != nil {
		return nil, err
	}

	return &validation.Refs{
		CertificateRefs: certRefsDER,
		RevocationRefs:  revocationRefsDER,
	}, nil
}

func TestSigner_SignWithValidationRefs(t *testing.T) {
	credential := certfixture.NewCredential(t)
	policy := policyfixture.Policy{
		UnsignedAttrs: []cades.AttributeName{
			cades.CertificateRefsAttr,
			cades.RevocationRefsAttr,
		},
	}
	validationProvider := &fakeValidationProvider{}

	cadesSigner := cades.Signer{
		Credential:         credential,
		HashAlg:            crypto.SHA256,
		Detached:           false,
		Policy:             policy,
		ValidationProvider: validationProvider,
	}

	sigDER, err := cadesSigner.Sign([]byte("Hello, CAdES AD-RV!"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if validationProvider.calls != 1 {
		t.Fatalf("expected validation provider to be called once, got %d", validationProvider.calls)
	}
	if validationProvider.cert == nil {
		t.Fatal("expected validation provider to receive signer certificate")
	}
	if len(validationProvider.chain) == 0 {
		t.Fatal("expected validation provider to receive certificate chain")
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
	if !strings.Contains(err.Error(), "validation provider is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSigner_SignWithEscTimeStamp(t *testing.T) {
	credential := certfixture.NewCredential(t)
	timestampCredential := certfixture.NewCredential(t)
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
	validationProvider := &fakeValidationProvider{}

	cadesSigner := cades.Signer{
		Credential:         credential,
		HashAlg:            crypto.SHA256,
		Detached:           false,
		Policy:             policy,
		TimeStampProvider:  timeStampProvider,
		ValidationProvider: validationProvider,
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
	if validationProvider.calls != 3 {
		t.Fatalf("expected validation provider to be called three times, got %d", validationProvider.calls)
	}
	externalChain := validationProvider.chains[1]
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
