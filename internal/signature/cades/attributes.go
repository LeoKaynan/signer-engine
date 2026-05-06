package cades

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"signer-engine/internal/cryptoutil"
	"signer-engine/internal/signature/cms"
	"time"
)

type AttributeName string

const SigningTimeAttr AttributeName = "signingTime"

func SigningTimeAttribute(t time.Time) (cms.Attribute, error) {
	der, err := asn1.Marshal(t.UTC())
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to marshal signing time: %w", err)
	}

	return cms.Attribute{
		AttrType: cms.OIDSigningTime,
		AttrValues: []asn1.RawValue{
			{FullBytes: der},
		},
	}, nil
}

const SigningCertificateV2Attr AttributeName = "signingCertificateV2Attribute"

func SigningCertificateV2Attribute(cert *x509.Certificate) (cms.Attribute, error) {
	certificateHash := sha256.Sum256(cert.Raw)

	payload := SigningCertificateV2{
		Certs: []ESSCertIDv2{
			{CertHash: certificateHash[:]},
		},
	}

	der, err := asn1.Marshal(payload)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to marshal signing certificate v2: %w", err)
	}

	return cms.Attribute{
		AttrType: OIDSigningCertificateV2,
		AttrValues: []asn1.RawValue{
			{FullBytes: der},
		},
	}, nil
}

const PolicyIdentifierAttr AttributeName = "policyIdentifier"

func PolicyIdentifierAttribute(policyOID asn1.ObjectIdentifier, hash []byte, uri string) (cms.Attribute, error) {
	payload := SignaturePolicyIdentifier{
		SigPolicyId: policyOID,
		SigPolicyHash: OtherHashAlgAndValue{
			HashAlgorithm: cms.AlgorithmIdentifier{
				Algorithm:  cryptoutil.OIDSHA256,
				Parameters: asn1.NullRawValue,
			},
			HashValue: hash,
		},
	}

	if uri != "" {
		payload.SigPolicyQualifiers = []SigPolicyQualifierInfo{
			{
				SigPolicyQualifierID: OIDSignaturePolicyQualifierURI,
				SigQualifier:         uri,
			},
		}
	}

	der, err := asn1.Marshal(payload)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to marshal signature policy identifier: %w", err)
	}

	return cms.Attribute{
		AttrType: OIDSignaturePolicyID,
		AttrValues: []asn1.RawValue{
			{FullBytes: der},
		},
	}, nil
}

const SignatureTimeStampTokenAttr AttributeName = "signatureTimeStampToken"

func SignatureTimeStampTokenAttribute(tokenDER []byte) (cms.Attribute, error) {
	if len(tokenDER) == 0 {
		return cms.Attribute{}, errors.New("token is empty")
	}

	return cms.Attribute{
		AttrType: OIDSignatureTimeStampToken,
		AttrValues: []asn1.RawValue{
			{FullBytes: tokenDER},
		},
	}, nil
}

const CertificateRefsAttr AttributeName = "certificateRefs"

func CertificateRefsAttribute(refsDER []byte) (cms.Attribute, error) {
	if len(refsDER) == 0 {
		return cms.Attribute{}, errors.New("refs are empty")
	}

	return cms.Attribute{
		AttrType: OIDCertificateRefs,
		AttrValues: []asn1.RawValue{
			{FullBytes: refsDER},
		},
	}, nil
}

const RevocationRefsAttr AttributeName = "revocationRefs"

func RevocationRefsAttribute(refsDER []byte) (cms.Attribute, error) {
	if len(refsDER) == 0 {
		return cms.Attribute{}, errors.New("revocation refs are empty")
	}
	return cms.Attribute{
		AttrType: OIDRevocationRefs,
		AttrValues: []asn1.RawValue{
			{FullBytes: refsDER},
		},
	}, nil
}

const EscTimeStampAttr AttributeName = "escTimeStamp"

func EscTimeStampAttribute(tokenDER []byte) (cms.Attribute, error) {
	if len(tokenDER) == 0 {
		return cms.Attribute{}, errors.New("esc timestamp token is empty")
	}
	return cms.Attribute{
		AttrType: OIDEscTimeStamp,
		AttrValues: []asn1.RawValue{
			{FullBytes: tokenDER},
		},
	}, nil
}
