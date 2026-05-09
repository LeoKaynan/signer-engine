package utils

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"testing"
	"time"

	"signer-engine/internal/cryptoutil"
	"signer-engine/internal/signature/cades"
	"signer-engine/internal/signature/cms"
)

func ParseCAdES(t testing.TB, der []byte) cms.SignedData {
	t.Helper()

	var contentInfo cms.ContentInfo
	if rest, err := asn1.Unmarshal(der, &contentInfo); err != nil {
		t.Fatalf("failed to unmarshal content info: %v", err)
	} else if len(rest) != 0 {
		t.Fatalf("unexpected trailing content info data: %x", rest)
	}
	if !contentInfo.ContentType.Equal(cms.OIDSignedData) {
		t.Fatalf("unexpected content type: got=%s want=%s", contentInfo.ContentType.String(), cms.OIDSignedData.String())
	}

	var signedData cms.SignedData
	if rest, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signedData); err != nil {
		t.Fatalf("failed to unmarshal signed data: %v", err)
	} else if len(rest) != 0 {
		t.Fatalf("unexpected trailing signed data: %x", rest)
	}

	return signedData
}

func RequireSingleSignerInfo(t testing.TB, signedData cms.SignedData) cms.SignerInfo {
	t.Helper()

	if len(signedData.SignerInfos) != 1 {
		t.Fatalf("expected one signer info entry, got %d", len(signedData.SignerInfos))
	}
	return signedData.SignerInfos[0]
}

func RequireSignedAttr(t testing.TB, signerInfo cms.SignerInfo, oid asn1.ObjectIdentifier) cms.Attribute {
	t.Helper()

	attr, ok := FindSignedAttr(signerInfo, oid)
	if !ok {
		t.Fatalf("expected signed attribute %s", oid.String())
	}
	return attr
}

func RequireUnsignedAttr(t testing.TB, signerInfo cms.SignerInfo, oid asn1.ObjectIdentifier) cms.Attribute {
	t.Helper()

	attr, ok := FindUnsignedAttr(signerInfo, oid)
	if !ok {
		t.Fatalf("expected unsigned attribute %s", oid.String())
	}
	return attr
}

func RequireNoUnsignedAttrs(t testing.TB, signerInfo cms.SignerInfo, context string) {
	t.Helper()

	if len(signerInfo.UnsignedAttrs) != 0 {
		t.Fatalf("%s should not include unsigned attributes, got %d", context, len(signerInfo.UnsignedAttrs))
	}
}

func RequireUnsignedAttrCount(t testing.TB, signerInfo cms.SignerInfo, count int) {
	t.Helper()

	if len(signerInfo.UnsignedAttrs) != count {
		t.Fatalf("expected %d unsigned attributes, got %d", count, len(signerInfo.UnsignedAttrs))
	}
}

func RequireOnlyUnsignedAttr(t testing.TB, signerInfo cms.SignerInfo, oid asn1.ObjectIdentifier) cms.Attribute {
	t.Helper()

	RequireUnsignedAttrCount(t, signerInfo, 1)
	attr := signerInfo.UnsignedAttrs[0]
	if !attr.AttrType.Equal(oid) {
		t.Fatalf("unexpected unsigned attribute: got=%s want=%s", attr.AttrType.String(), oid.String())
	}
	return attr
}

func RequireUnsignedAttrs(t testing.TB, signerInfo cms.SignerInfo, oids ...asn1.ObjectIdentifier) {
	t.Helper()

	RequireUnsignedAttrCount(t, signerInfo, len(oids))
	for _, oid := range oids {
		RequireUnsignedAttr(t, signerInfo, oid)
	}
}

func AssertTimestampTokenAttribute(t testing.TB, attr cms.Attribute) cms.SignedData {
	t.Helper()

	var contentInfo cms.ContentInfo
	unmarshalSingleAttrValue(t, attr, &contentInfo)
	if !contentInfo.ContentType.Equal(cms.OIDSignedData) {
		t.Fatalf(
			"unexpected timestamp token content type: got=%s want=%s",
			contentInfo.ContentType.String(),
			cms.OIDSignedData.String(),
		)
	}

	var signedData cms.SignedData
	if rest, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signedData); err != nil {
		t.Fatalf("failed to unmarshal timestamp token signed data: %v", err)
	} else if len(rest) != 0 {
		t.Fatalf("unexpected trailing timestamp token signed data: %x", rest)
	}

	return signedData
}

func AssertASN1AttributeValue(t testing.TB, attr cms.Attribute) {
	t.Helper()

	var value asn1.RawValue
	unmarshalSingleAttrValue(t, attr, &value)
	if len(value.FullBytes) == 0 {
		t.Fatalf("attribute %s has empty ASN.1 value", attr.AttrType.String())
	}
}

func AssertContentMode(t testing.TB, signedData cms.SignedData, content []byte, detached bool) {
	t.Helper()

	if !signedData.EncapContentInfo.EContentType.Equal(cms.OIDData) {
		t.Fatalf(
			"unexpected encapsulated content type: got=%s want=%s",
			signedData.EncapContentInfo.EContentType.String(),
			cms.OIDData.String(),
		)
	}

	if detached {
		if len(signedData.EncapContentInfo.EContent) != 0 {
			t.Fatal("detached signature should not include encapsulated content")
		}
		return
	}

	if !bytes.Equal(signedData.EncapContentInfo.EContent, content) {
		t.Fatalf("attached signature content mismatch: got=%x want=%x", signedData.EncapContentInfo.EContent, content)
	}
}

func AssertContentType(t testing.TB, attr cms.Attribute, expected asn1.ObjectIdentifier) {
	t.Helper()

	var got asn1.ObjectIdentifier
	unmarshalSingleAttrValue(t, attr, &got)
	if !got.Equal(expected) {
		t.Fatalf("unexpected content type attribute: got=%s want=%s", got.String(), expected.String())
	}
}

func AssertMessageDigest(t testing.TB, attr cms.Attribute, content []byte) {
	t.Helper()

	var got []byte
	unmarshalSingleAttrValue(t, attr, &got)

	expected := sha256.Sum256(content)
	if !bytes.Equal(got, expected[:]) {
		t.Fatalf("unexpected message digest: got=%x want=%x", got, expected)
	}
}

func AssertSigningTime(t testing.TB, attr cms.Attribute, expected time.Time) {
	t.Helper()

	var got time.Time
	unmarshalSingleAttrValue(t, attr, &got)
	if !got.UTC().Equal(expected.UTC()) {
		t.Fatalf("unexpected signing time: got=%s want=%s", got.UTC(), expected.UTC())
	}
}

func AssertSigningCertificateV2(t testing.TB, attr cms.Attribute, cert *x509.Certificate) {
	t.Helper()

	var got struct {
		Certs []struct {
			HashAlgorithm cms.AlgorithmIdentifier `asn1:"optional"`
			CertHash      []byte
		}
	}
	unmarshalSingleAttrValue(t, attr, &got)
	if len(got.Certs) != 1 {
		t.Fatalf("expected one signing-certificate-v2 cert entry, got %d", len(got.Certs))
	}
	if len(got.Certs[0].HashAlgorithm.Algorithm) != 0 &&
		!got.Certs[0].HashAlgorithm.Algorithm.Equal(cryptoutil.OIDSHA256) {
		t.Fatalf("unexpected signing-certificate-v2 hash algorithm: got=%s want=%s",
			got.Certs[0].HashAlgorithm.Algorithm.String(),
			cryptoutil.OIDSHA256.String(),
		)
	}

	expected := sha256.Sum256(cert.Raw)
	if !bytes.Equal(got.Certs[0].CertHash, expected[:]) {
		t.Fatalf("unexpected signing-certificate-v2 cert hash: got=%x want=%x", got.Certs[0].CertHash, expected)
	}
}

func AssertSignerInfoSID(t testing.TB, signerInfo cms.SignerInfo, cert *x509.Certificate) {
	t.Helper()

	if !bytes.Equal(signerInfo.SID.Issuer.FullBytes, cert.RawIssuer) {
		t.Fatalf("unexpected signer info issuer: got=%x want=%x", signerInfo.SID.Issuer.FullBytes, cert.RawIssuer)
	}
	if signerInfo.SID.SerialNumber == nil || signerInfo.SID.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatalf("unexpected signer info serial: got=%v want=%v", signerInfo.SID.SerialNumber, cert.SerialNumber)
	}
}

func AssertSHA256DigestAlgorithms(t testing.TB, signedData cms.SignedData, signerInfo cms.SignerInfo) {
	t.Helper()

	if len(signedData.DigestAlgorithms) != 1 {
		t.Fatalf("expected one signed data digest algorithm, got %d", len(signedData.DigestAlgorithms))
	}
	if !signedData.DigestAlgorithms[0].Algorithm.Equal(cryptoutil.OIDSHA256) {
		t.Fatalf(
			"unexpected signed data digest algorithm: got=%s want=%s",
			signedData.DigestAlgorithms[0].Algorithm.String(),
			cryptoutil.OIDSHA256.String(),
		)
	}
	if !signerInfo.DigestAlgorithm.Algorithm.Equal(cryptoutil.OIDSHA256) {
		t.Fatalf(
			"unexpected signer info digest algorithm: got=%s want=%s",
			signerInfo.DigestAlgorithm.Algorithm.String(),
			cryptoutil.OIDSHA256.String(),
		)
	}
}

func AssertSignedDataCertificates(t testing.TB, signedData cms.SignedData, certs ...*x509.Certificate) {
	t.Helper()

	if len(signedData.Certificates) != len(certs) {
		t.Fatalf("expected exactly %d CMS certificates, got %d", len(certs), len(signedData.Certificates))
	}

	parsed := make([]*x509.Certificate, 0, len(signedData.Certificates))
	for _, raw := range signedData.Certificates {
		cert, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			t.Fatalf("failed to parse CMS certificate: %v", err)
		}
		parsed = append(parsed, cert)
	}

	for _, expected := range certs {
		found := false
		for _, got := range parsed {
			if bytes.Equal(got.Raw, expected.Raw) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected CMS certificate not found: subject=%s serial=%s", expected.Subject, expected.SerialNumber)
		}
	}
}

func FindSignedAttr(signerInfo cms.SignerInfo, oid asn1.ObjectIdentifier) (cms.Attribute, bool) {
	return findAttr(signerInfo.SignedAttrs, oid)
}

func FindUnsignedAttr(signerInfo cms.SignerInfo, oid asn1.ObjectIdentifier) (cms.Attribute, bool) {
	return findAttr(signerInfo.UnsignedAttrs, oid)
}

func AssertSignaturePolicyIdentifier(
	t testing.TB,
	attr cms.Attribute,
	expectedOID asn1.ObjectIdentifier,
	expectedHash []byte,
	expectedURI string,
) {
	t.Helper()

	if len(attr.AttrValues) != 1 {
		t.Fatalf("expected one signature policy value, got %d", len(attr.AttrValues))
	}

	var policyID cades.SignaturePolicyIdentifier
	if rest, err := asn1.Unmarshal(attr.AttrValues[0].FullBytes, &policyID); err != nil {
		t.Fatalf("failed to unmarshal signature policy identifier: %v", err)
	} else if len(rest) != 0 {
		t.Fatalf("unexpected trailing signature policy identifier data: %x", rest)
	}

	if !policyID.SigPolicyId.Equal(expectedOID) {
		t.Fatalf("unexpected policy OID: got=%s want=%s", policyID.SigPolicyId.String(), expectedOID.String())
	}
	if !policyID.SigPolicyHash.HashAlgorithm.Algorithm.Equal(cryptoutil.OIDSHA256) {
		t.Fatalf(
			"unexpected policy hash algorithm: got=%s want=%s",
			policyID.SigPolicyHash.HashAlgorithm.Algorithm.String(),
			cryptoutil.OIDSHA256.String(),
		)
	}
	if !bytes.Equal(policyID.SigPolicyHash.HashValue, expectedHash) {
		t.Fatalf("unexpected policy hash: got=%x want=%x", policyID.SigPolicyHash.HashValue, expectedHash)
	}
	if len(policyID.SigPolicyQualifiers) != 1 {
		t.Fatalf("expected one policy qualifier, got %d", len(policyID.SigPolicyQualifiers))
	}
	if got := policyID.SigPolicyQualifiers[0].SigQualifier; got != expectedURI {
		t.Fatalf("unexpected policy URI: got=%q want=%q", got, expectedURI)
	}
}

func findAttr(attrs []cms.Attribute, oid asn1.ObjectIdentifier) (cms.Attribute, bool) {
	for _, attr := range attrs {
		if attr.AttrType.Equal(oid) {
			return attr, true
		}
	}
	return cms.Attribute{}, false
}

func unmarshalSingleAttrValue(t testing.TB, attr cms.Attribute, dst any) {
	t.Helper()

	if len(attr.AttrValues) != 1 {
		t.Fatalf("expected one attribute value for %s, got %d", attr.AttrType.String(), len(attr.AttrValues))
	}
	if rest, err := asn1.Unmarshal(attr.AttrValues[0].FullBytes, dst); err != nil {
		t.Fatalf("failed to unmarshal attribute %s: %v", attr.AttrType.String(), err)
	} else if len(rest) != 0 {
		t.Fatalf("unexpected trailing attribute %s data: %x", attr.AttrType.String(), rest)
	}
}
