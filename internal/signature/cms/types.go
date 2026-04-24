package cms

import (
	"encoding/asn1"
	"math/big"
)

// RFC5652 3. General Syntax
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// RFC5280 4.1.1.2 signatureAlgorithm
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// RFC5652 5.2 EncapsulatedContentInfo Type
type EncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,tag:0,optional"`
}

// RFC5652 10.2.4 IssuerAndSerialNumber
type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// RFC5652 5.3 SignerInfo Type
type Attribute struct {
	AttrType   asn1.ObjectIdentifier
	AttrValues []asn1.RawValue `asn1:"set"`
}

// RFC5652 5.3 SignerInfo Type
type SignerInfo struct {
	Version            int
	SID                IssuerAndSerialNumber
	DigestAlgorithm    AlgorithmIdentifier
	SignedAttrs        []Attribute `asn1:"tag:0,implicit,optional,set"`
	SignatureAlgorithm AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      []Attribute `asn1:"tag:1,implicit,optional,set"`
}

// RFC5652 5.1  SignedData Type
type SignedData struct {
	Version          int
	DigestAlgorithms []AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo EncapsulatedContentInfo
	Certificates     []asn1.RawValue `asn1:"tag:0,implicit,optional,set"`
	CRLs             []asn1.RawValue `asn1:"tag:1,implicit,optional,set"`
	SignerInfos      []SignerInfo    `asn1:"set"`
}
