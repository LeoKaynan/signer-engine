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
// Serial signing at AD-RC/AD-RA appends the new signer's certs/CRLs and a new
// VRI entry to the existing DSS, then issues a new DocTimeStamp (and a new
// ArchiveTimeStamp for AD-RA). Earlier DocTimeStamps remain valid because the
// merge is performed as an incremental update.
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

	signingTime := s.Clock.Now()
	signed, err := s.embedSignature(pdfBytes, withTimestamp, signOptions{
		PlaceholderSize: signaturePlaceholderSize(withTimestamp),
		ReuseEmptyField: true,
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

// applyDSSAndDocumentTimestamp seals the signature with LTV material:
//
//  1. DSS update with the signer's chain + CRLs + PBAD artifacts, indexed by
//     the signature's /Contents hash.
//  2. DocTimeStamp covering everything so far.
//  3. DSS update with the TSA's chain + CRLs, indexed by the DocTimeStamp's
//     /Contents hash — so the DocTimeStamp itself is self-validating.
//  4. For AD-RA: ArchiveTimeStamp, then another DSS update with its TSA chain.
//
// Each signed object that lands in the PDF (signature, DocTimeStamp,
// ArchiveTimeStamp) gets its own VRI entry, which is what ETSI EN 319 142-1
// PAdES-LTA expects.
func (s *Signer) applyDSSAndDocumentTimestamp(signed []byte, signingTime time.Time, level signaturepolicy.Level) ([]byte, error) {
	leaf := s.Credential.Certificate()
	chain := s.Credential.Chain()

	signerMaterial, err := s.TrustMaterialExtractor.FromCertificate(context.Background(), leaf, chain)
	if err != nil {
		return nil, fmt.Errorf("pades: extract trust material for DSS: %w", err)
	}
	// FromCertificate populates Chain from the input chain plus any discovered
	// issuers; pass leaf explicitly so it lands first.
	signerMaterial.Leaf = leaf

	withSigDSS, err := s.appendDSS(signed, signerMaterial, signingTime, s.PBADArtifacts, "signature DSS")
	if err != nil {
		return nil, err
	}

	withDocTS, err := s.appendDocTimestampWithDSS(withSigDSS, "DocTimeStamp", signingTime)
	if err != nil {
		return nil, err
	}

	if level < signaturepolicy.LevelA {
		return withDocTS, nil
	}

	return s.appendDocTimestampWithDSS(withDocTS, "ArchiveTimeStamp", signingTime)
}

// appendDocTimestampWithDSS adds a DocTimeStamp (or ArchiveTimeStamp) and
// follows it with a DSS incremental update carrying the TSA's chain and CRLs,
// indexed by the timestamp's /Contents hash.
func (s *Signer) appendDocTimestampWithDSS(pdf []byte, fieldName string, signingTime time.Time) ([]byte, error) {
	withTS, tokenDER, err := addDocumentTimestamp(pdf, fieldName, s.stamp)
	if err != nil {
		return nil, fmt.Errorf("pades: add %s: %w", fieldName, err)
	}
	slog.Info("pades: timestamp added", "field", fieldName, "token_bytes", len(tokenDER))

	tsaMaterial, err := s.TrustMaterialExtractor.FromTimestampToken(context.Background(), tokenDER)
	if err != nil {
		return nil, fmt.Errorf("pades: extract TSA trust material for %s: %w", fieldName, err)
	}
	if tsaMaterial == nil {
		return withTS, nil
	}

	return s.appendDSS(withTS, tsaMaterial, signingTime, nil, fmt.Sprintf("%s DSS", fieldName))
}

func (s *Signer) appendDSS(pdf []byte, material *validation.TrustMaterial, signingTime time.Time, pbad *PBADArtifacts, label string) ([]byte, error) {
	certDERs := material.FlatCertDERs()
	crlDERs := material.FlatCRLDERs()
	result, _, err := addDSS(pdf, certDERs, crlDERs, signingTime, pbad)
	if err != nil {
		return nil, fmt.Errorf("pades: add %s: %w", label, err)
	}
	slog.Info("pades: DSS added", "label", label, "certs", len(certDERs), "crls", len(crlDERs))
	return result, nil
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
