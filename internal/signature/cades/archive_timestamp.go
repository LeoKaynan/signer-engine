package cades

import (
	"encoding/asn1"
	"errors"
	"fmt"

	"signer-engine/internal/signature/cms"
)

func ArchiveTimeStampV2Input(ctx cms.UnsignedAttributeContext, attrs []cms.Attribute) ([]byte, error) {
	if len(ctx.EncapContentInfo.EContentType) == 0 {
		return nil, errors.New("encapsulated content info is required")
	}

	encapContentInfoDER, err := asn1.Marshal(ctx.EncapContentInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal encapsulated content info: %w", err)
	}

	input := append([]byte(nil), encapContentInfoDER...)
	if ctx.Detached {
		input = append(input, ctx.Data...)
	}

	if len(ctx.Certificates) > 0 {
		certificatesDER, err := asn1.MarshalWithParams(ctx.Certificates, "tag:0,implicit,set")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal certificates: %w", err)
		}
		input = append(input, certificatesDER...)
	}

	if len(ctx.CRLs) > 0 {
		crlsDER, err := asn1.MarshalWithParams(ctx.CRLs, "tag:1,implicit,set")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal CRLs: %w", err)
		}
		input = append(input, crlsDER...)
	}

	signerInfo := ctx.SignerInfo
	signerInfo.UnsignedAttrs = attrs
	signerInfoBytes, err := signerInfoDataElements(signerInfo)
	if err != nil {
		return nil, err
	}

	return append(input, signerInfoBytes...), nil
}

func signerInfoDataElements(signerInfo cms.SignerInfo) ([]byte, error) {
	signerInfoDER, err := asn1.Marshal(signerInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signer info: %w", err)
	}

	var raw asn1.RawValue
	if rest, err := asn1.Unmarshal(signerInfoDER, &raw); err != nil {
		return nil, fmt.Errorf("failed to decode signer info: %w", err)
	} else if len(rest) != 0 {
		return nil, errors.New("unexpected trailing signer info data")
	}
	if raw.Tag != asn1.TagSequence || !raw.IsCompound {
		return nil, errors.New("signer info is not a sequence")
	}

	return append([]byte(nil), raw.Bytes...), nil
}
