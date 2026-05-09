package cades

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"signer-engine/internal/cryptoutil"
	"signer-engine/internal/signature/cms"
)

func BuildCertificateRefs(certs []*x509.Certificate) ([]byte, error) {
	refs := make([]otherCertID, 0, len(certs))
	for _, cert := range certs {
		if cert == nil {
			return nil, errors.New("certificate refs contains nil certificate")
		}

		ref, err := newOtherCertID(cert)
		if err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}

	der, err := asn1.Marshal(refs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal complete certificate refs: %w", err)
	}

	return der, nil
}

func BuildCertificateValues(certs []*x509.Certificate) ([]byte, error) {
	values := make([]asn1.RawValue, 0, len(certs))
	for _, cert := range certs {
		if cert == nil {
			return nil, errors.New("certificate values contains nil certificate")
		}

		values = append(values, asn1.RawValue{FullBytes: cert.Raw})
	}

	der, err := asn1.Marshal(values)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate values: %w", err)
	}

	return der, nil
}

func BuildRevocationRefs(crls []*x509.RevocationList) ([]byte, error) {
	refs := make([]crlOcspRef, 0, len(crls))
	for _, crl := range crls {
		if crl == nil {
			return nil, errors.New("revocation refs contains nil CRL")
		}

		crlID, err := newCRLValidatedID(crl)
		if err != nil {
			return nil, err
		}
		refs = append(refs, crlOcspRef{
			CRLIDs: crlListID{CRLs: []crlValidatedID{crlID}},
		})
	}

	der, err := asn1.Marshal(refs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal complete revocation refs: %w", err)
	}

	return der, nil
}

func BuildRevocationValues(crls []*x509.RevocationList) ([]byte, error) {
	values := revocationValues{
		CRLVals: make([]asn1.RawValue, 0, len(crls)),
	}
	for _, crl := range crls {
		if crl == nil {
			return nil, errors.New("revocation values contains nil CRL")
		}
		values.CRLVals = append(values.CRLVals, asn1.RawValue{FullBytes: crl.Raw})
	}

	der, err := asn1.Marshal(values)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal revocation values: %w", err)
	}

	return der, nil
}

func newOtherCertID(cert *x509.Certificate) (otherCertID, error) {
	if cert.SerialNumber == nil {
		return otherCertID{}, errors.New("certificate serial number is required")
	}

	hash := sha256.Sum256(cert.Raw)
	return otherCertID{
		OtherCertHash: newSHA256OtherHash(hash[:]),
		IssuerSerial: issuerSerial{
			Issuer:       directoryNameGeneralNames(cert.RawIssuer),
			SerialNumber: cert.SerialNumber,
		},
	}, nil
}

func newCRLValidatedID(crl *x509.RevocationList) (crlValidatedID, error) {
	if len(crl.Raw) == 0 {
		return crlValidatedID{}, errors.New("CRL raw DER is required")
	}

	hash := sha256.Sum256(crl.Raw)
	id := crlIdentifier{
		CRLIssuer:     asn1.RawValue{FullBytes: crl.RawIssuer},
		CRLIssuedTime: crl.ThisUpdate,
		CRLNumber:     crl.Number,
	}

	return crlValidatedID{
		CRLHash:       newSHA256OtherHash(hash[:]),
		CRLIdentifier: id,
	}, nil
}

func newSHA256OtherHash(hash []byte) otherHashAlgAndValue {
	return otherHashAlgAndValue{
		HashAlgorithm: cms.AlgorithmIdentifier{
			Algorithm: cryptoutil.OIDSHA256,
		},
		HashValue: append([]byte(nil), hash...),
	}
}

func directoryNameGeneralNames(rawName []byte) []asn1.RawValue {
	return []asn1.RawValue{
		{
			Class:      asn1.ClassContextSpecific,
			Tag:        4,
			IsCompound: true,
			Bytes:      rawName,
		},
	}
}

type otherCertID struct {
	OtherCertHash otherHashAlgAndValue
	IssuerSerial  issuerSerial `asn1:"optional"`
}

type issuerSerial struct {
	Issuer       []asn1.RawValue
	SerialNumber *big.Int
}

type otherHashAlgAndValue struct {
	HashAlgorithm cms.AlgorithmIdentifier
	HashValue     []byte
}

type crlOcspRef struct {
	CRLIDs crlListID `asn1:"explicit,tag:0,optional"`
}

type crlListID struct {
	CRLs []crlValidatedID
}

type crlValidatedID struct {
	CRLHash       otherHashAlgAndValue
	CRLIdentifier crlIdentifier `asn1:"optional"`
}

type crlIdentifier struct {
	CRLIssuer     asn1.RawValue
	CRLIssuedTime time.Time
	CRLNumber     *big.Int `asn1:"optional"`
}

type revocationValues struct {
	CRLVals []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}
