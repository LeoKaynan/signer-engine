package cades

import (
	"encoding/asn1"
	"errors"
	"fmt"

	"signer-engine/internal/signature/cms"
)

// ArchiveTimeStampV2Input builds the hash input for the id-aa-ets-archiveTimestampV2
// attribute as defined in RFC 5126 §6.4.1:
//
//	messageImprint = hash( encapContentInfo
//	                    || externalContent          (if detached)
//	                    || Certificates [0]         (when present)
//	                    || crls [1]                 (when present)
//	                    || SignerInfo inner bytes )  (excluding later ATSv2 tokens)
//
// attrs contains the unsigned attributes that precede this ATSv2 in the SignerInfo.
// They replace UnsignedAttrs in the hash input so that the token seals exactly the
// attributes already present — not any future ones (RFC 5126 §6.4.1, last paragraph).
func ArchiveTimeStampV2Input(ctx cms.UnsignedAttributeContext, attrs []cms.Attribute) ([]byte, error) {
	if len(ctx.EncapContentInfo.EContentType) == 0 {
		return nil, errors.New("encapsulated content info is required")
	}

	// Segment 1: encapContentInfo SEQUENCE (RFC 5126 §6.4.1, bullet 1).
	encapContentInfoDER, err := asn1.Marshal(ctx.EncapContentInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal encapsulated content info: %w", err)
	}

	input := append([]byte(nil), encapContentInfoDER...)

	// Segment 1b: external content bytes when the signature is detached
	// (RFC 5126 §6.4.1, bullet 2).
	if ctx.Detached {
		input = append(input, ctx.Data...)
	}

	// Segment 2: Certificates [0] IMPLICIT SET — the full A0-tagged field.
	// This is why co-signing invalidates an existing ATSv2: adding a co-signer's
	// certificate chain changes this segment, breaking the hash (RFC 5126 §6.4.1,
	// bullet 3). Renewal recalculates the token over the merged certificate set.
	if len(ctx.Certificates) > 0 {
		certificatesDER, err := asn1.MarshalWithParams(ctx.Certificates, "tag:0,implicit,set")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal certificates: %w", err)
		}
		input = append(input, certificatesDER...)
	}

	// Segment 3: crls [1] IMPLICIT SET (RFC 5126 §6.4.1, bullet 3).
	if len(ctx.CRLs) > 0 {
		crlsDER, err := asn1.MarshalWithParams(ctx.CRLs, "tag:1,implicit,set")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal CRLs: %w", err)
		}
		input = append(input, crlsDER...)
	}

	// Segment 4: SignerInfo inner bytes (without the outer SEQUENCE wrapper),
	// with UnsignedAttrs set to attrs — which excludes any later ATSv2 tokens
	// (RFC 5126 §6.4.1, bullet 4 and last paragraph).
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
