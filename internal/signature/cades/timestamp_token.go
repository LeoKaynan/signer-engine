package cades

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"signer-engine/internal/signature/cms"
)

type TimestampTokenCertificates struct {
	Signer *x509.Certificate
	Chain  []*x509.Certificate
	All    []*x509.Certificate
}

func TimestampTokenCertificateInfo(tokenDER []byte) TimestampTokenCertificates {
	contentInfo, signedData, ok := parseTimestampSignedData(tokenDER)
	if !ok || !contentInfo.ContentType.Equal(cms.OIDSignedData) {
		return TimestampTokenCertificates{}
	}

	certs := certificatesFromSignedData(signedData)
	if len(certs) == 0 || len(signedData.SignerInfos) == 0 {
		return TimestampTokenCertificates{All: certs}
	}

	signerInfo := signedData.SignerInfos[0]
	var signer *x509.Certificate
	var chain []*x509.Certificate
	for _, cert := range certs {
		if cert.SerialNumber.Cmp(signerInfo.SID.SerialNumber) == 0 &&
			bytes.Equal(cert.RawIssuer, signerInfo.SID.Issuer.FullBytes) {
			signer = cert
			continue
		}
		chain = append(chain, cert)
	}

	if signer == nil {
		return TimestampTokenCertificates{All: certs}
	}

	return TimestampTokenCertificates{
		Signer: signer,
		Chain:  chain,
		All:    certs,
	}
}

func EnrichTimestampTokenWithRefs(
	tokenDER []byte,
	certRefsDER []byte,
	revRefsDER []byte,
	certValuesDER []byte,
	revValuesDER []byte,
) ([]byte, error) {
	contentInfo, signedData, ok := parseTimestampSignedData(tokenDER)
	if !ok || len(signedData.SignerInfos) == 0 {
		return tokenDER, nil
	}

	certRefsAttr, err := CertificateRefsAttribute(certRefsDER)
	if err != nil {
		return nil, err
	}
	revRefsAttr, err := RevocationRefsAttribute(revRefsDER)
	if err != nil {
		return nil, err
	}

	attrs := []cms.Attribute{certRefsAttr, revRefsAttr}
	if len(certValuesDER) > 0 && len(revValuesDER) > 0 {
		certValuesAttr, err := CertValuesAttribute(certValuesDER)
		if err != nil {
			return nil, err
		}
		revValuesAttr, err := RevocationValuesAttribute(revValuesDER)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, certValuesAttr, revValuesAttr)
	}

	// RFC 5126 6.2.1 and 6.2.2 specify that refs for TSUs that issued
	// timestamp tokens are added to the relevant token's signedData as
	// signerInfos unsignedAttrs.
	// https://www.rfc-editor.org/rfc/rfc5126#section-6.2.1
	signedData.SignerInfos[0].UnsignedAttrs = replaceUnsignedAttrs(
		signedData.SignerInfos[0].UnsignedAttrs,
		attrs...,
	)

	signedDataDER, err := asn1.Marshal(signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal enriched timestamp signed data: %w", err)
	}

	contentInfo.Content = asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      signedDataDER,
	}
	enrichedDER, err := asn1.Marshal(contentInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal enriched timestamp token: %w", err)
	}

	return enrichedDER, nil
}

func parseTimestampSignedData(tokenDER []byte) (cms.ContentInfo, cms.SignedData, bool) {
	var contentInfo cms.ContentInfo
	if _, err := asn1.Unmarshal(tokenDER, &contentInfo); err != nil {
		return cms.ContentInfo{}, cms.SignedData{}, false
	}
	if !contentInfo.ContentType.Equal(cms.OIDSignedData) || len(contentInfo.Content.Bytes) == 0 {
		return contentInfo, cms.SignedData{}, false
	}

	var signedData cms.SignedData
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signedData); err != nil {
		return contentInfo, cms.SignedData{}, false
	}

	return contentInfo, signedData, true
}

func certificatesFromSignedData(signedData cms.SignedData) []*x509.Certificate {
	certs := make([]*x509.Certificate, 0, len(signedData.Certificates))
	for _, raw := range signedData.Certificates {
		cert, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}
	return certs
}

func replaceUnsignedAttrs(existing []cms.Attribute, attrs ...cms.Attribute) []cms.Attribute {
	out := make([]cms.Attribute, 0, len(existing)+len(attrs))
	for _, existingAttr := range existing {
		var replaced bool
		for _, attr := range attrs {
			if existingAttr.AttrType.Equal(attr.AttrType) {
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, existingAttr)
		}
	}
	return append(out, attrs...)
}

func appendCertificateSet(base []*x509.Certificate, extra ...*x509.Certificate) []*x509.Certificate {
	out := append([]*x509.Certificate(nil), base...)

	for _, cert := range extra {
		if cert == nil {
			continue
		}

		var exists bool
		for _, existing := range out {
			if existing != nil && bytes.Equal(existing.Raw, cert.Raw) {
				exists = true
				break
			}
		}
		if !exists {
			out = append(out, cert)
		}
	}

	return out
}
