package cms

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"fmt"
	"log/slog"
	"signer-engine/internal/cryptoutil"
	"signer-engine/internal/signer"
)

type UnsignedAttributeContext struct {
	Signature        []byte
	HashAlg          crypto.Hash
	Data             []byte
	Detached         bool
	EncapContentInfo EncapsulatedContentInfo
	Certificates     []asn1.RawValue
	CRLs             []asn1.RawValue
	SignerInfo       SignerInfo
}

type UnsignedAttributeBuilder func(ctx UnsignedAttributeContext) ([]Attribute, error)

type Builder struct {
	Credential               signer.Credential
	HashAlg                  crypto.Hash
	Detached                 bool
	ExtraSignedAttributes    []Attribute
	UnsignedAttributeBuilder UnsignedAttributeBuilder
}

func (b *Builder) Build(data []byte) ([]byte, error) {
	signerInfo, encapsulatedContentInfo, certificates, err := b.buildSignerInfo(data)
	if err != nil {
		return nil, fmt.Errorf("failed to build signer info: %w", err)
	}

	signedData := SignedData{
		// RFC5652 5.1 SignedData Type
		// version is the syntax version number.  The appropriate value
		// depends on certificates, eContentType, and SignerInfo.
		Version: 1,
		DigestAlgorithms: []AlgorithmIdentifier{
			{
				Algorithm:  cryptoutil.OIDSHA256,
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
	slog.Info("cms: signed data marshaled", "bytes", len(signedDataBytes))

	contentInfo := ContentInfo{
		ContentType: OIDSignedData,
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
	slog.Info("cms: content info marshaled", "bytes", len(contentInfoBytes))

	return contentInfoBytes, nil
}

func (b *Builder) CoSign(existingCMS []byte, originalData []byte) ([]byte, error) {
	var contentInfo ContentInfo
	if _, err := asn1.Unmarshal(existingCMS, &contentInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal content info: %w", err)
	}

	var signedData SignedData
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signedData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal signed data: %w", err)
	}

	cert := b.Credential.Certificate()
	for _, existing := range signedData.SignerInfos {
		if bytes.Equal(existing.SID.Issuer.FullBytes, cert.RawIssuer) &&
			existing.SID.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return nil, fmt.Errorf("certificate already present in signature: serial=%s", cert.SerialNumber)
		}
	}

	originalDetached := b.Detached
	defer func() { b.Detached = originalDetached }()
	b.Detached = signedData.EncapContentInfo.EContent == nil

	documentData := signedData.EncapContentInfo.EContent
	if len(documentData) == 0 {
		if len(originalData) == 0 {
			return nil, fmt.Errorf("co-signing detached signatures requires the original document")
		}
		documentData = originalData
	}

	signerInfo, _, certificates, err := b.buildSignerInfo(documentData)
	if err != nil {
		return nil, fmt.Errorf("failed to build signer info: %w", err)
	}

	signedData.SignerInfos = append(signedData.SignerInfos, signerInfo)
	signedData.Certificates = append(signedData.Certificates, certificates...)

	hasAlg := false
	for _, alg := range signedData.DigestAlgorithms {
		if alg.Algorithm.Equal(cryptoutil.OIDSHA256) {
			hasAlg = true
			break
		}
	}
	if !hasAlg {
		signedData.DigestAlgorithms = append(signedData.DigestAlgorithms, AlgorithmIdentifier{
			Algorithm:  cryptoutil.OIDSHA256,
			Parameters: asn1.NullRawValue,
		})
	}

	signedDataBytes, err := asn1.Marshal(signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signed data: %w", err)
	}

	contentInfo.Content = asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      signedDataBytes,
	}

	contentInfoBytes, err := asn1.Marshal(contentInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal content info: %w", err)
	}
	slog.Info("cms: content info marshaled", "bytes", len(contentInfoBytes))

	return contentInfoBytes, nil
}

func (b *Builder) buildSignerInfo(data []byte) (SignerInfo, EncapsulatedContentInfo, []asn1.RawValue, error) {
	certificates := []asn1.RawValue{
		{FullBytes: b.Credential.Certificate().Raw},
	}

	for _, c := range b.Credential.Chain() {
		certificates = append(certificates, asn1.RawValue{FullBytes: c.Raw})
	}

	encapsulatedContentInfo := EncapsulatedContentInfo{EContentType: OIDData}
	if !b.Detached {
		encapsulatedContentInfo.EContent = data
	}

	slog.Info("cms: building signed data",
		"hash", b.HashAlg.String(),
		"detached", b.Detached,
		"data_bytes", len(data),
	)

	dataHash := b.HashAlg.New()
	dataHash.Write(data)
	messageDigest := dataHash.Sum(nil)
	slog.Info("cms: message digest calculated", "bytes", len(messageDigest))

	messageDigestValueDER, err := asn1.Marshal(messageDigest)
	if err != nil {
		return SignerInfo{}, EncapsulatedContentInfo{}, []asn1.RawValue{}, fmt.Errorf("failed to marshal message digest value: %w", err)
	}

	contentTypeValueDER, err := asn1.Marshal(OIDData)
	if err != nil {
		return SignerInfo{}, EncapsulatedContentInfo{}, []asn1.RawValue{}, fmt.Errorf("failed to marshal content type value: %w", err)
	}

	signedAttrs := []Attribute{
		RawAttribute(IdContentType, contentTypeValueDER),
		RawAttribute(IdMessageDigest, messageDigestValueDER),
	}

	signedAttrs = append(signedAttrs, b.ExtraSignedAttributes...)
	slog.Info("cms: signed attributes prepared",
		"count", len(signedAttrs),
		"extra", len(b.ExtraSignedAttributes),
	)

	// RFC5652 5.4 Message Digest Calculation Process
	// The IMPLICIT [0] tag in the signedAttrs is not used for the DER encoding, rather an EXPLICIT SET OF tag is used.
	signedAttrsDER, err := asn1.MarshalWithParams(signedAttrs, "set")
	if err != nil {
		return SignerInfo{}, EncapsulatedContentInfo{}, []asn1.RawValue{}, fmt.Errorf("failed to marshal message digest attribute: %w", err)
	}
	slog.Info("cms: signed attributes marshaled", "bytes", len(signedAttrsDER))

	toBeSignedHash := b.HashAlg.New()
	toBeSignedHash.Write(signedAttrsDER)
	toBeSignedBytes := toBeSignedHash.Sum(nil)

	slog.Info("cms: signing authenticated attributes")
	signature, err := b.Credential.Sign(toBeSignedBytes, b.HashAlg)
	if err != nil {
		return SignerInfo{}, EncapsulatedContentInfo{}, []asn1.RawValue{}, fmt.Errorf("failed to sign: %w", err)
	}
	slog.Info("cms: authenticated attributes signed", "signature_bytes", len(signature))

	signerInfo := SignerInfo{
		// RFC5652 5.3 SignerInfo Type
		// version is the syntax version number. If the SignerIdentifier is
		// the CHOICE issuerAndSerialNumber, then the version MUST be 1. If
		// the SignerIdentifier is subjectKeyIdentifier, then the version
		// MUST be 3
		Version: 1,
		SID: IssuerAndSerialNumber{
			Issuer: asn1.RawValue{
				FullBytes: b.Credential.Certificate().RawIssuer,
			},
			SerialNumber: b.Credential.Certificate().SerialNumber,
		},
		DigestAlgorithm: AlgorithmIdentifier{
			Algorithm:  cryptoutil.OIDSHA256,
			Parameters: asn1.NullRawValue,
		},
		SignedAttrs: signedAttrs,
		SignatureAlgorithm: AlgorithmIdentifier{
			Algorithm:  cryptoutil.OIDRSAEncryption,
			Parameters: asn1.NullRawValue,
		},
		Signature: signature,
	}

	var unsignedAttrs []Attribute
	if b.UnsignedAttributeBuilder != nil {
		slog.Info("cms: building unsigned attributes")
		unsignedAttrs, err = b.UnsignedAttributeBuilder(UnsignedAttributeContext{
			Signature:        signature,
			HashAlg:          b.HashAlg,
			Data:             data,
			Detached:         b.Detached,
			EncapContentInfo: encapsulatedContentInfo,
			Certificates:     certificates,
			SignerInfo:       signerInfo,
		})
		if err != nil {
			return SignerInfo{}, EncapsulatedContentInfo{}, []asn1.RawValue{}, fmt.Errorf("failed to build unsigned attributes: %w", err)
		}
		slog.Info("cms: unsigned attributes built", "count", len(unsignedAttrs))
	} else {
		slog.Info("cms: no unsigned attributes configured")
	}
	signerInfo.UnsignedAttrs = unsignedAttrs

	return signerInfo, encapsulatedContentInfo, certificates, nil
}
