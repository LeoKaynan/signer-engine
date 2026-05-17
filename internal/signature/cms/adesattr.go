package cms

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"signer-engine/internal/cryptoutil"
	"time"
)

// AdES CMS attribute identifiers and structured builders shared by CAdES and
// PAdES. These are defined by RFC 5035 (ESS), RFC 5126 (CAdES baseline) and
// RFC 3161 (timestamping) — generic CMS attributes that any AdES profile built
// on top of CMS can rely on. Identifiers use the Id* prefix to mirror the
// ASN.1 names (id-aa-*) from the source RFCs.

var (
	// RFC5035 §3 / §5.4.1 — id-aa-signingCertificateV2
	IdSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}

	// RFC5126 §5.8.1 — id-aa-ets-sigPolicyId
	IdSignaturePolicy = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 15}

	// RFC5126 §5.8.1 / DOC-ICP-15.03 v9.1 p.21 — id-spq-ets-uri
	IdSpqEtsURI = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 5, 1}

	// RFC3161 Appendix A — id-aa-signatureTimeStampToken
	IdSignatureTimeStampToken = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
)

// RFC5035 §4 / §5.4.1.1 — ESSCertIDv2
type ESSCertIDv2 struct {
	// hashAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256}
	HashAlgorithm *AlgorithmIdentifier `asn1:"optional"`
	CertHash      []byte
}

// RFC5035 §3 / §5.4.1 — SigningCertificateV2
type SigningCertificateV2 struct {
	Certs []ESSCertIDv2
}

// RFC5126 §5.8.1 — OtherHashAlgAndValue
type OtherHashAlgAndValue struct {
	HashAlgorithm AlgorithmIdentifier
	HashValue     []byte
}

// RFC5126 §5.8.1 — SignaturePolicyIdentifier
type SignaturePolicyIdentifier struct {
	SigPolicyId         asn1.ObjectIdentifier
	SigPolicyHash       OtherHashAlgAndValue
	SigPolicyQualifiers []SigPolicyQualifierInfo `asn1:"optional"`
}

type SigPolicyQualifierInfo struct {
	SigPolicyQualifierID asn1.ObjectIdentifier
	SigQualifier         string `asn1:"ia5"`
}

// SigningTimeAttribute returns the RFC 5652 §11.3 signing-time signed attribute.
//
// Format-specific note: CAdES adds this attribute explicitly. PAdES forbids it
// (ETSI EN 319 142-1 §5.4.1) and represents signing time via the PDF /M field.
// XAdES uses the <xades:SigningTime> XML element instead. Callers must respect
// their format's rules.
func SigningTimeAttribute(t time.Time) (Attribute, error) {
	der, err := asn1.Marshal(t.UTC())
	if err != nil {
		return Attribute{}, fmt.Errorf("failed to marshal signing time: %w", err)
	}
	return RawAttribute(IdSigningTime, der), nil
}

// SigningCertificateV2Attribute returns the RFC 5035 signing-certificate-v2 signed attribute.
func SigningCertificateV2Attribute(cert *x509.Certificate) (Attribute, error) {
	certificateHash := sha256.Sum256(cert.Raw)

	payload := SigningCertificateV2{
		Certs: []ESSCertIDv2{
			{CertHash: certificateHash[:]},
		},
	}

	der, err := asn1.Marshal(payload)
	if err != nil {
		return Attribute{}, fmt.Errorf("failed to marshal signing certificate v2: %w", err)
	}
	return RawAttribute(IdSigningCertificateV2, der), nil
}

// PolicyIdentifierAttribute returns the RFC 5126 §5.8.1 signature-policy-identifier signed attribute.
func PolicyIdentifierAttribute(policyOID asn1.ObjectIdentifier, hash []byte, uri string) (Attribute, error) {
	payload := SignaturePolicyIdentifier{
		SigPolicyId: policyOID,
		SigPolicyHash: OtherHashAlgAndValue{
			HashAlgorithm: AlgorithmIdentifier{
				Algorithm:  cryptoutil.OIDSHA256,
				Parameters: asn1.NullRawValue,
			},
			HashValue: hash,
		},
	}

	if uri != "" {
		payload.SigPolicyQualifiers = []SigPolicyQualifierInfo{
			{
				SigPolicyQualifierID: IdSpqEtsURI,
				SigQualifier:         uri,
			},
		}
	}

	der, err := asn1.Marshal(payload)
	if err != nil {
		return Attribute{}, fmt.Errorf("failed to marshal signature policy identifier: %w", err)
	}
	return RawAttribute(IdSignaturePolicy, der), nil
}
