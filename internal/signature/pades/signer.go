package pades

import (
	"context"
	"crypto"
	"fmt"
	"log/slog"

	"signer-engine/internal/signature/cms"
	"signer-engine/internal/signature/signaturepolicy"
	"signer-engine/internal/signer"
	"signer-engine/internal/tsa"
	"signer-engine/internal/validation"
	"time"
)

// PBADArtifacts holds the ICP-Brasil policy artifacts required for AD-RC/AD-RA
// DSS entries as defined in DOC-ICP-15.03 Anexo 4.
type PBADArtifacts struct {
	PolicyArtifact []byte
	LpaArtifact    []byte
	LpaSignature   []byte
}

// PBADArtifactSource is an optional interface implemented by policies that can
// describe the URLs needed to fetch the PBAD artifacts (PA, LPA, LPA sig).
// It is used by the factory layer to populate Signer.PBADArtifacts at level C+.
type PBADArtifactSource interface {
	PBADArtifactURLs() (policyURL, lpaArtifactURL, lpaSignatureURL string)
}

// Signer produces PAdES signatures over PDF documents.
type Signer struct {
	Credential             signer.Credential
	Policy                 Policy
	HashAlg                crypto.Hash
	TimeStampProvider      tsa.Provider
	TrustMaterialExtractor validation.TrustMaterialExtractor
	Clock                  signaturepolicy.Clock
	PBADArtifacts          *PBADArtifacts
}

// stamp requests a timestamp from the configured provider and returns the
// raw token DER. Used by signature timestamps, DocTimeStamp and ArchiveTimeStamp.
func (s *Signer) stamp(data []byte) ([]byte, error) {
	if s.TimeStampProvider == nil {
		return nil, fmt.Errorf("pades: time stamp provider is required")
	}
	token, err := s.TimeStampProvider.Stamp(context.Background(), data, s.HashAlg)
	if err != nil {
		return nil, err
	}
	return token.TokenDER, nil
}

// Sign implements signaturepolicy.Signer. It embeds a PAdES signature into
// input.Data (the PDF) and returns the signed PDF.
//
// If input.Data already contains a PAdES signature (detected by DocMDP), this
// transparently performs serial signing — reusing one of the empty signature
// fields pre-allocated by the first signature. Otherwise it performs the
// first signature, reserving extra empty fields so future calls can append
// serially without breaking DocMDP=2 integrity.
//
// input.ExistingSignature is ignored for PAdES — serial signing is detected
// from the PDF state itself, not from external CMS bytes.
//
// Serial signing currently supports AD-RB and AD-RT only. AD-RC and AD-RA
// serial signing requires merging the new signer's certs/CRLs into the
// existing DSS, which is not yet implemented.
func (s *Signer) Sign(input signaturepolicy.SignInput) ([]byte, error) {
	alreadySigned, err := IsAlreadySigned(input.Data)
	if err != nil {
		return nil, err
	}
	if alreadySigned {
		return s.signSerial(input.Data)
	}
	return s.signFirst(input.Data)
}

func (s *Signer) signFirst(pdfBytes []byte) ([]byte, error) {
	level, withTimestamp, withDSS, err := s.validateAndLevel()
	if err != nil {
		return nil, err
	}

	signingTime := s.Clock.Now()
	signed, err := s.embedSignature(pdfBytes, withTimestamp, signOptions{
		PlaceholderSize: signaturePlaceholderSize(withTimestamp),
		ReserveFields:   reservedSerialFields,
		SigningTime:     signingTime,
	})
	if err != nil {
		return nil, err
	}

	if !withDSS {
		return signed, nil
	}

	return s.applyDSSAndDocumentTimestamp(signed, signingTime, level)
}

func (s *Signer) signSerial(pdfBytes []byte) ([]byte, error) {
	level, withTimestamp, withDSS, err := s.validateAndLevel()
	if err != nil {
		return nil, err
	}
	if withDSS {
		return nil, fmt.Errorf("pades: serial signing not yet supported for level %d (AD-RC and above)", level)
	}

	signingTime := s.Clock.Now()
	return s.embedSignature(pdfBytes, withTimestamp, signOptions{
		PlaceholderSize: signaturePlaceholderSize(withTimestamp),
		ReuseEmptyField: true,
		SigningTime:     signingTime,
	})
}

// validateAndLevel checks required configuration and returns the effective level
// plus precomputed flags for timestamp and DSS.
func (s *Signer) validateAndLevel() (level signaturepolicy.Level, withTimestamp, withDSS bool, err error) {
	if s.HashAlg == 0 {
		return 0, false, false, fmt.Errorf("pades: hash algorithm is required")
	}

	if err := signaturepolicy.ValidatePolicyPrerequisites(s.Policy, s.HashAlg, s.Credential.Certificate(), s.Credential.Chain()); err != nil {
		return 0, false, false, fmt.Errorf("pades: %w", err)
	}

	level = signaturepolicy.LevelB
	if s.Policy != nil {
		level = s.Policy.Level()
	}
	withTimestamp = level >= signaturepolicy.LevelT
	withDSS = level >= signaturepolicy.LevelC

	if withDSS {
		if s.TimeStampProvider == nil {
			return 0, false, false, fmt.Errorf("pades: time stamp provider is required for AD-RC and above")
		}
		if s.TrustMaterialExtractor == nil {
			return 0, false, false, fmt.Errorf("pades: trust material extractor is required for AD-RC and above")
		}
	}
	return level, withTimestamp, withDSS, nil
}

func signaturePlaceholderSize(withTimestamp bool) int {
	if withTimestamp {
		return placeholderSizeTimestamp
	}
	return placeholderSizeBase
}

// embedSignature appends a PAdES incremental update containing the signature
// CMS, retrying with a larger placeholder if the produced CMS overflows.
func (s *Signer) embedSignature(pdfBytes []byte, withTimestamp bool, opts signOptions) ([]byte, error) {
	placeholderSize := opts.PlaceholderSize
	for attempt := 0; attempt < maxSignRetries; attempt++ {
		opts.PlaceholderSize = placeholderSize

		out, cs, ce, err := buildPDFWithPlaceholder(pdfBytes, opts)
		if err != nil {
			return nil, fmt.Errorf("pades: failed to build PDF with placeholder: %w", err)
		}
		slog.Info("pades: placeholder PDF built", "bytes", len(out), "contents_start", cs, "contents_end", ce)

		out, err = patchLastByteRange(out, cs, ce)
		if err != nil {
			return nil, fmt.Errorf("pades: failed to patch ByteRange: %w", err)
		}

		// bytes to sign: everything except the /Contents hex placeholder
		toSign := make([]byte, 0, len(out)-int(ce-cs))
		toSign = append(toSign, out[:cs]...)
		toSign = append(toSign, out[ce:]...)

		cmsDER, err := s.buildCMS(toSign, withTimestamp)
		if err != nil {
			return nil, fmt.Errorf("pades: failed to build CMS: %w", err)
		}
		slog.Info("pades: CMS built", "bytes", len(cmsDER))

		final, ok, err := patchLastContents(out, cmsDER)
		if err != nil {
			return nil, fmt.Errorf("pades: failed to patch /Contents: %w", err)
		}
		if ok {
			slog.Info("pades: signature embedded", "total_bytes", len(final))
			return final, nil
		}

		slog.Info("pades: signature exceeded placeholder, retrying", "attempt", attempt+1, "placeholder", placeholderSize)
		placeholderSize *= 2
	}

	return nil, fmt.Errorf("pades: signature did not fit in placeholder after %d retries", maxSignRetries)
}

// applyDSSAndDocumentTimestamp adds a DSS incremental update with validation material,
// followed by one or two document timestamps depending on level.
func (s *Signer) applyDSSAndDocumentTimestamp(signed []byte, signingTime time.Time, level signaturepolicy.Level) ([]byte, error) {
	leaf := s.Credential.Certificate()
	chain := s.Credential.Chain()

	trustMaterial, err := s.TrustMaterialExtractor.FromCertificate(context.Background(), leaf, chain)
	if err != nil {
		return nil, fmt.Errorf("pades: extract trust material for DSS: %w", err)
	}
	// FromCertificate populates Chain from the input chain plus any discovered
	// issuers; pass leaf explicitly so it lands first.
	trustMaterial.Leaf = leaf
	certDERs := trustMaterial.FlatCertDERs()
	crlDERs := trustMaterial.FlatCRLDERs()

	withDSS, _, err := addDSS(signed, certDERs, crlDERs, signingTime, s.PBADArtifacts)
	if err != nil {
		return nil, fmt.Errorf("pades: add DSS: %w", err)
	}
	slog.Info("pades: DSS added", "certs", len(certDERs), "crls", len(crlDERs))

	withDocTS, err := addDocumentTimestamp(withDSS, "DocTimeStamp", s.stamp)
	if err != nil {
		return nil, fmt.Errorf("pades: add DocTimeStamp: %w", err)
	}
	slog.Info("pades: DocTimeStamp added")

	if level < signaturepolicy.LevelA {
		return withDocTS, nil
	}

	// AD-RA: additional archive document timestamp covering the DocTimeStamp revision.
	withArchiveTS, err := addDocumentTimestamp(withDocTS, "ArchiveTimeStamp", s.stamp)
	if err != nil {
		return nil, fmt.Errorf("pades: add ArchiveTimeStamp: %w", err)
	}
	slog.Info("pades: ArchiveTimeStamp added")
	return withArchiveTS, nil
}

// buildCMS produces a detached CMS (ContentInfo) for toSign.
// If withTimestamp is true, a signature timestamp token is added as an unsigned attribute.
// Signing-time is intentionally omitted — PAdES forbids the id-signing-time attribute.
func (s *Signer) buildCMS(toSign []byte, withTimestamp bool) ([]byte, error) {
	var extraSignedAttrs []cms.Attribute

	if s.Policy != nil {
		ctx := SigningContext{
			Certificate: s.Credential.Certificate(),
			Chain:       s.Credential.Chain(),
			HashAlg:     s.HashAlg,
		}
		attrs, err := s.Policy.SignedAttributes(ctx)
		if err != nil {
			return nil, fmt.Errorf("pades: build policy signed attributes: %w", err)
		}
		extraSignedAttrs = attrs
	}

	builder := &cms.Builder{
		Credential:            s.Credential,
		HashAlg:               s.HashAlg,
		Detached:              true,
		ExtraSignedAttributes: extraSignedAttrs,
	}

	if withTimestamp {
		builder.UnsignedAttributeBuilder = func(ctx cms.UnsignedAttributeContext) ([]cms.Attribute, error) {
			tokenDER, err := s.stamp(ctx.Signature)
			if err != nil {
				return nil, fmt.Errorf("pades: request signature timestamp: %w", err)
			}
			slog.Info("pades: signature timestamp embedded", "bytes", len(tokenDER))
			return []cms.Attribute{cms.RawAttribute(cms.IdSignatureTimeStampToken, tokenDER)}, nil
		}
	}

	return builder.Build(toSign)
}
