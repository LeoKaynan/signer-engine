package cades

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"signer-engine/internal/constants"
	"signer-engine/internal/signature/cms"
	"time"
)

func SigningTimeAttribute(t time.Time) (cms.Attribute, error) {
	der, err := asn1.Marshal(t.UTC())
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to marshal signing time: %w", err)
	}

	return cms.Attribute{
		AttrType: constants.OIDSigningTime,
		AttrValues: []asn1.RawValue{
			{FullBytes: der},
		},
	}, nil
}

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
		AttrType: constants.OIDSigningCertificateV2,
		AttrValues: []asn1.RawValue{
			{FullBytes: der},
		},
	}, nil
}

func PolicyIdentifierAttribute(policyOID asn1.ObjectIdentifier, hash []byte) (cms.Attribute, error) {
	payload := SignaturePolicyIdentifier{
		SigPolicyId: policyOID,
		SigPolicyHash: OtherHashAlgAndValue{
			HashAlgorithm: &cms.AlgorithmIdentifier{
				Algorithm:  constants.OIDSHA256,
				Parameters: asn1.NullRawValue,
			},
			HashValue: hash,
		},
	}

	der, err := asn1.Marshal(payload)
	if err != nil {
		return cms.Attribute{}, fmt.Errorf("failed to marshal signature policy identifier: %w", err)
	}

	return cms.Attribute{
		AttrType: constants.OIDSignaturePolicyId,
		AttrValues: []asn1.RawValue{
			{FullBytes: der},
		},
	}, nil
}
