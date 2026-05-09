package cades

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"math/big"
	"testing"

	"signer-engine/internal/cryptoutil"
	"signer-engine/internal/signature/cms"
)

func TestArchiveTimeStampV2Input(t *testing.T) {
	valueDER, err := asn1.Marshal([]byte("value"))
	if err != nil {
		t.Fatalf("marshal value: %v", err)
	}
	attr := cms.Attribute{
		AttrType: OIDCertValues,
		AttrValues: []asn1.RawValue{
			{FullBytes: valueDER},
		},
	}
	ctx := cms.UnsignedAttributeContext{
		HashAlg:  crypto.SHA256,
		Data:     []byte("external-content"),
		Detached: true,
		EncapContentInfo: cms.EncapsulatedContentInfo{
			EContentType: cms.OIDData,
		},
		Certificates: []asn1.RawValue{
			{FullBytes: []byte{0x30, 0x00}},
		},
		SignerInfo: cms.SignerInfo{
			Version: 1,
			SID: cms.IssuerAndSerialNumber{
				Issuer:       asn1.RawValue{FullBytes: []byte{0x30, 0x00}},
				SerialNumber: big.NewInt(1),
			},
			DigestAlgorithm: cms.AlgorithmIdentifier{
				Algorithm: cryptoutil.OIDSHA256,
			},
			SignatureAlgorithm: cms.AlgorithmIdentifier{
				Algorithm: cryptoutil.OIDRSAEncryption,
			},
			Signature: []byte{0x01, 0x02, 0x03},
		},
	}

	input, err := ArchiveTimeStampV2Input(ctx, []cms.Attribute{attr})
	if err != nil {
		t.Fatalf("ArchiveTimeStampV2Input failed: %v", err)
	}

	encapDER, err := asn1.Marshal(ctx.EncapContentInfo)
	if err != nil {
		t.Fatalf("marshal encap content info: %v", err)
	}
	certificatesDER, err := asn1.MarshalWithParams(ctx.Certificates, "tag:0,implicit,set")
	if err != nil {
		t.Fatalf("marshal certificates: %v", err)
	}
	signerInfo := ctx.SignerInfo
	signerInfo.UnsignedAttrs = []cms.Attribute{attr}
	signerInfoBytes, err := signerInfoDataElements(signerInfo)
	if err != nil {
		t.Fatalf("signer info bytes: %v", err)
	}

	expected := append([]byte(nil), encapDER...)
	expected = append(expected, ctx.Data...)
	expected = append(expected, certificatesDER...)
	expected = append(expected, signerInfoBytes...)

	if !bytes.Equal(input, expected) {
		t.Fatal("unexpected archive timestamp input")
	}
}

func TestArchiveTimeStampV2Input_DetachedContentOnlyWhenNeeded(t *testing.T) {
	ctx := cms.UnsignedAttributeContext{
		Data: []byte("embedded-content"),
		EncapContentInfo: cms.EncapsulatedContentInfo{
			EContentType: cms.OIDData,
			EContent:     []byte("embedded-content"),
		},
		SignerInfo: cms.SignerInfo{
			Version: 1,
			SID: cms.IssuerAndSerialNumber{
				Issuer:       asn1.RawValue{FullBytes: []byte{0x30, 0x00}},
				SerialNumber: big.NewInt(1),
			},
			DigestAlgorithm: cms.AlgorithmIdentifier{
				Algorithm: cryptoutil.OIDSHA256,
			},
			SignatureAlgorithm: cms.AlgorithmIdentifier{
				Algorithm: cryptoutil.OIDRSAEncryption,
			},
			Signature: []byte{0x01},
		},
	}

	input, err := ArchiveTimeStampV2Input(ctx, nil)
	if err != nil {
		t.Fatalf("ArchiveTimeStampV2Input failed: %v", err)
	}
	if bytes.Count(input, ctx.Data) != 1 {
		t.Fatal("expected embedded content only inside encapContentInfo")
	}
}

func TestArchiveTimeStampV2Input_RequiresEncapContentInfo(t *testing.T) {
	_, err := ArchiveTimeStampV2Input(cms.UnsignedAttributeContext{}, nil)
	if err == nil {
		t.Fatal("expected missing encap content info error")
	}
}
