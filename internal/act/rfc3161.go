package act

import (
	"crypto"
	"encoding/asn1"
	"errors"
	"fmt"

	"signer-engine/internal/cryptoutil"
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type messageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

type timeStampRequest struct {
	Version        int
	MessageImprint messageImprint
	CertReq        bool `asn1:"optional"`
}

type pkiStatusInfo struct {
	Status       int
	StatusString []string       `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

const (
	pkiStatusGranted                = 0
	pkiStatusGrantedWithMods        = 1
	pkiStatusRejection              = 2
	pkiStatusWaiting                = 3
	pkiStatusRevocationWarning      = 4
	pkiStatusRevocationNotification = 5
)

// BuildRequest returns a DER-encoded RFC 3161 TimeStampReq.
func BuildRequest(input []byte, hashAlg crypto.Hash) ([]byte, error) {
	if len(input) == 0 {
		return nil, errors.New("timestamp input is required")
	}

	oid, err := hashOID(hashAlg)
	if err != nil {
		return nil, err
	}
	if !hashAlg.Available() {
		return nil, fmt.Errorf("hash algorithm is not available: %v", hashAlg)
	}

	hash := hashAlg.New()
	if _, err := hash.Write(input); err != nil {
		return nil, fmt.Errorf("failed to hash timestamp input: %w", err)
	}

	return asn1.Marshal(timeStampRequest{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: algorithmIdentifier{
				Algorithm: oid,
			},
			HashedMessage: hash.Sum(nil),
		},
		CertReq: true,
	})
}

func hashOID(hashAlg crypto.Hash) (asn1.ObjectIdentifier, error) {
	switch hashAlg {
	case crypto.SHA1:
		return cryptoutil.OIDSHA1, nil
	case crypto.SHA224:
		return cryptoutil.OIDSHA224, nil
	case crypto.SHA256:
		return cryptoutil.OIDSHA256, nil
	case crypto.SHA384:
		return cryptoutil.OIDSHA384, nil
	case crypto.SHA512:
		return cryptoutil.OIDSHA512, nil
	default:
		return nil, fmt.Errorf("unsupported timestamp hash algorithm: %v", hashAlg)
	}
}

// ExtractToken accepts either a raw RFC 3161 TimeStampToken or a TimeStampResp
// and returns the embedded token DER.
func ExtractToken(der []byte) ([]byte, error) {
	if len(der) == 0 {
		return nil, errors.New("timestamp response is empty")
	}

	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp response: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("timestamp response has trailing data")
	}

	// TimeStampToken is a CMS ContentInfo whose first child is an OID.
	if token, ok := contentInfoDER(outer); ok {
		return token, nil
	}

	// TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken ContentInfo OPTIONAL }
	if outer.Tag != asn1.TagSequence || !outer.IsCompound {
		return nil, errors.New("timestamp response is not a sequence")
	}

	rest = outer.Bytes
	var status pkiStatusInfo
	rest, err = asn1.Unmarshal(rest, &status)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp status: %w", err)
	}
	if err := validateTimestampStatus(status); err != nil {
		return nil, err
	}
	if len(rest) == 0 {
		return nil, errors.New("timestamp response does not contain a token")
	}

	var token asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &token)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp token: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("timestamp response has trailing fields")
	}

	if tokenDER, ok := contentInfoDER(token); ok {
		return tokenDER, nil
	}

	return nil, errors.New("timestamp response token is not a CMS ContentInfo")
}

func validateTimestampStatus(status pkiStatusInfo) error {
	switch status.Status {
	case pkiStatusGranted, pkiStatusGrantedWithMods:
		return nil
	case pkiStatusRejection, pkiStatusWaiting, pkiStatusRevocationWarning, pkiStatusRevocationNotification:
		return fmt.Errorf("timestamp request was not granted: status=%s%s", timestampStatusName(status.Status), timestampStatusDetails(status))
	default:
		return fmt.Errorf("timestamp request returned unknown status: %d%s", status.Status, timestampStatusDetails(status))
	}
}

func timestampStatusName(status int) string {
	switch status {
	case pkiStatusGranted:
		return "granted"
	case pkiStatusGrantedWithMods:
		return "grantedWithMods"
	case pkiStatusRejection:
		return "rejection"
	case pkiStatusWaiting:
		return "waiting"
	case pkiStatusRevocationWarning:
		return "revocationWarning"
	case pkiStatusRevocationNotification:
		return "revocationNotification"
	default:
		return fmt.Sprintf("unknown(%d)", status)
	}
}

func timestampStatusDetails(status pkiStatusInfo) string {
	var details string
	if len(status.StatusString) > 0 {
		details += fmt.Sprintf(", message=%q", status.StatusString)
	}
	if len(status.FailInfo.Bytes) > 0 {
		details += fmt.Sprintf(", failInfo=%x", status.FailInfo.Bytes)
	}
	return details
}

func contentInfoDER(value asn1.RawValue) ([]byte, bool) {
	if value.Tag != asn1.TagSequence || !value.IsCompound {
		return nil, false
	}

	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(value.Bytes, &oid); err != nil {
		return nil, false
	}

	return value.FullBytes, true
}
