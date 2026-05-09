package validation

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"

	"signer-engine/internal/signature/cms"
)

func timestampTokenSignerChain(tokenDER []byte) (*x509.Certificate, []*x509.Certificate, error) {
	contentInfo, signedData, ok := parseTimestampSignedData(tokenDER)
	if !ok || !contentInfo.ContentType.Equal(cms.OIDSignedData) {
		return nil, nil, nil
	}

	certs := certificatesFromSignedData(signedData)
	if len(certs) == 0 || len(signedData.SignerInfos) == 0 {
		return nil, nil, nil
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
		return nil, nil, nil
	}

	return signer, chain, nil
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
