package cms

import (
	"crypto"
	"encoding/asn1"
	"fmt"
	"signer-engine/internal/constants"
	"signer-engine/internal/keystore"
)

type Builder struct {
	Signer   keystore.Signer
	HashAlg  crypto.Hash
	Detached bool
}

func (b *Builder) Build(data []byte) ([]byte, error) {
	dataHash := b.HashAlg.New()
	dataHash.Write(data)
	messageDigest := dataHash.Sum(nil)

	messageDigestValueDER, err := asn1.Marshal(messageDigest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal message digest value: %w", err)
	}

	contentTypeValueDER, err := asn1.Marshal(constants.OIDData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal content type value: %w", err)
	}

	signedAttrs := []Attribute{
		{
			AttrType: constants.OIDContentType,
			AttrValues: []asn1.RawValue{
				{FullBytes: contentTypeValueDER},
			},
		},
		{
			AttrType: constants.OIDMessageDigest,
			AttrValues: []asn1.RawValue{
				{FullBytes: messageDigestValueDER},
			},
		},
	}

	// RFC5652 5.4 Message Digest Calculation Process
	// The IMPLICIT [0] tag in the signedAttrs is not used for the DER encoding, rather an EXPLICIT SET OF tag is used.
	signedAttrsDER, err := asn1.MarshalWithParams(signedAttrs, "set")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal message digest attribute: %w", err)
	}

	toBeSignedHash := b.HashAlg.New()
	toBeSignedHash.Write(signedAttrsDER)
	toBeSignedBytes := toBeSignedHash.Sum(nil)

	signature, err := b.Signer.Sign(toBeSignedBytes, b.HashAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	signerInfo := SignerInfo{
		// RFC5652 5.3 SignerInfo Type
		// version is the syntax version number. If the SignerIdentifier is
		// the CHOICE issuerAndSerialNumber, then the version MUST be 1. If
		// the SignerIdentifier is subjectKeyIdentifier, then the version
		// MUST be 3
		Version: 1,
		SID: IssuerAndSerialNumber{
			Issuer: asn1.RawValue{
				FullBytes: b.Signer.Certificate().RawIssuer,
			},
			SerialNumber: b.Signer.Certificate().SerialNumber,
		},
		DigestAlgorithm: AlgorithmIdentifier{
			Algorithm:  constants.OIDSHA256,
			Parameters: asn1.NullRawValue,
		},
		SignedAttrs: signedAttrs,
		SignatureAlgorithm: AlgorithmIdentifier{
			Algorithm:  constants.OIDRSAEncryption,
			Parameters: asn1.NullRawValue,
		},
		Signature: signature,
	}

	certificates := []asn1.RawValue{
		{FullBytes: b.Signer.Certificate().Raw},
	}

	for _, c := range b.Signer.Chain() {
		certificates = append(certificates, asn1.RawValue{FullBytes: c.Raw})
	}

	encapsulatedContentInfo := EncapsulatedContentInfo{EContentType: constants.OIDData}
	if !b.Detached {
		encapsulatedContentInfo.EContent = data
	}

	signedData := SignedData{
		// RFC5652 5.1 SignedData Type
		// version is the syntax version number.  The appropriate value
		// depends on certificates, eContentType, and SignerInfo.
		Version: 1,
		DigestAlgorithms: []AlgorithmIdentifier{
			{
				Algorithm:  constants.OIDSHA256,
				Parameters: asn1.NullRawValue,
			},
		},
		EncapContentInfo: encapsulatedContentInfo,
		Certificates:     certificates,
		SignerInfos: []SignerInfo{
			signerInfo,
		},
	}

	signedDataBytes, err := asn1.Marshal(signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signed data: %w", err)
	}

	contentInfo := ContentInfo{
		ContentType: constants.OIDSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      signedDataBytes,
		},
	}

	contentInfoBytes, err := asn1.Marshal(contentInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal content info: %w", err)
	}

	return contentInfoBytes, nil
}
