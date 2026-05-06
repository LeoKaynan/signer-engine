package cades

import (
	"encoding/asn1"
	"errors"
	"fmt"

	"signer-engine/internal/signature/cms"
)

func EscTimeStampInput(signature []byte, attrs []cms.Attribute) ([]byte, error) {
	if len(signature) == 0 {
		return nil, errors.New("signature is required")
	}
	if len(attrs) == 0 {
		return nil, errors.New("unsigned attributes are required")
	}

	input := append([]byte(nil), signature...)
	for _, attr := range attrs {
		attrBytes, err := unsignedAttributeBytes(attr)
		if err != nil {
			return nil, err
		}
		input = append(input, attrBytes...)
	}

	return input, nil
}

func unsignedAttributeBytes(attr cms.Attribute) ([]byte, error) {
	if len(attr.AttrType) == 0 {
		return nil, errors.New("attribute type is required")
	}

	oidDER, err := asn1.Marshal(attr.AttrType)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attribute type: %w", err)
	}

	valuesDER, err := asn1.MarshalWithParams(attr.AttrValues, "set")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attribute values: %w", err)
	}

	return append(oidDER, valuesDER...), nil
}
