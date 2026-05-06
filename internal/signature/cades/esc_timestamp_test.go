package cades

import (
	"bytes"
	"encoding/asn1"
	"testing"

	"signer-engine/internal/signature/cms"
)

func TestEscTimeStampInput(t *testing.T) {
	signature := []byte("signature")
	valueDER, err := asn1.Marshal([]byte("value"))
	if err != nil {
		t.Fatalf("marshal value: %v", err)
	}

	attr := cms.Attribute{
		AttrType: OIDSignatureTimeStampToken,
		AttrValues: []asn1.RawValue{
			{FullBytes: valueDER},
		},
	}

	input, err := EscTimeStampInput(signature, []cms.Attribute{attr})
	if err != nil {
		t.Fatalf("EscTimeStampInput failed: %v", err)
	}

	attrBytes, err := unsignedAttributeBytes(attr)
	if err != nil {
		t.Fatalf("unsignedAttributeBytes failed: %v", err)
	}

	expected := append([]byte(nil), signature...)
	expected = append(expected, attrBytes...)

	if !bytes.Equal(input, expected) {
		t.Fatal("unexpected escrow timestamp input")
	}
}

func TestUnsignedAttributeBytes(t *testing.T) {
	valueDER, err := asn1.Marshal([]byte("value"))
	if err != nil {
		t.Fatalf("marshal value: %v", err)
	}

	attr := cms.Attribute{
		AttrType: OIDCertificateRefs,
		AttrValues: []asn1.RawValue{
			{FullBytes: valueDER},
		},
	}

	got, err := unsignedAttributeBytes(attr)
	if err != nil {
		t.Fatalf("unsignedAttributeBytes failed: %v", err)
	}

	oidDER, err := asn1.Marshal(OIDCertificateRefs)
	if err != nil {
		t.Fatalf("marshal oid: %v", err)
	}
	valuesDER, err := asn1.MarshalWithParams(attr.AttrValues, "set")
	if err != nil {
		t.Fatalf("marshal values: %v", err)
	}

	expected := append(oidDER, valuesDER...)
	if !bytes.Equal(got, expected) {
		t.Fatal("unexpected unsigned attribute bytes")
	}
}

func TestEscTimeStampInput_RequiresSignature(t *testing.T) {
	_, err := EscTimeStampInput(nil, []cms.Attribute{{AttrType: OIDCertificateRefs}})
	if err == nil {
		t.Fatal("expected missing signature error")
	}
}

func TestEscTimeStampInput_RequiresAttributes(t *testing.T) {
	_, err := EscTimeStampInput([]byte("signature"), nil)
	if err == nil {
		t.Fatal("expected missing attributes error")
	}
}
