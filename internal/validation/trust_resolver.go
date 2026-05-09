package validation

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
)

type SignatureTrustResolver struct {
	extractor         TrustMaterialExtractor
	signerCert        *x509.Certificate
	signerChain       []*x509.Certificate
	timestampMaterial []*TrustMaterial
	signerMaterial    *TrustMaterial
}

func NewSignatureTrustResolver(extractor TrustMaterialExtractor) *SignatureTrustResolver {
	return &SignatureTrustResolver{
		extractor: extractor,
	}
}

func (r *SignatureTrustResolver) SetSigner(cert *x509.Certificate, chain []*x509.Certificate) error {
	if cert == nil {
		return errors.New("signing certificate is required")
	}

	r.signerCert = cert
	r.signerChain = append([]*x509.Certificate(nil), chain...)
	r.timestampMaterial = nil
	r.signerMaterial = nil
	return nil
}

func (r *SignatureTrustResolver) AddTimestampToken(ctx context.Context, tokenDER []byte) (*TrustMaterial, error) {
	if r.extractor == nil {
		return nil, errors.New("trust material extractor is required")
	}
	material, err := r.extractor.FromTimestampToken(ctx, tokenDER)
	if err != nil {
		return nil, err
	}
	if material == nil {
		return nil, nil
	}

	introducedCertificate := r.materialIntroducesCertificate(material)
	r.timestampMaterial = append(r.timestampMaterial, material)
	if introducedCertificate {
		r.signerMaterial = nil
	}
	return material, nil
}

func (r *SignatureTrustResolver) SignerMaterial(ctx context.Context) (*TrustMaterial, error) {
	if r.signerMaterial != nil {
		return r.signerMaterial, nil
	}
	if r.signerCert == nil {
		return nil, errors.New("signing certificate is required")
	}
	if r.extractor == nil {
		return nil, errors.New("trust material extractor is required")
	}

	certificates := appendCertificateSet(nil, r.signerChain...)
	for _, timestamp := range r.timestampMaterial {
		certificates = appendCertificateSet(certificates, trustMaterialCertificates(timestamp)...)
	}

	material, err := r.extractor.FromCertificate(ctx, r.signerCert, certificates)
	if err != nil {
		return nil, err
	}
	r.signerMaterial = material
	return material, nil
}

func trustMaterialCertificates(material *TrustMaterial) []*x509.Certificate {
	if material == nil {
		return nil
	}

	certs := appendCertificateSet(nil, material.Chain...)
	return appendCertificateSet(certs, material.Leaf)
}

func (r *SignatureTrustResolver) materialIntroducesCertificate(material *TrustMaterial) bool {
	known := appendCertificateSet(nil, r.signerCert)
	known = appendCertificateSet(known, r.signerChain...)
	for _, timestamp := range r.timestampMaterial {
		known = appendCertificateSet(known, trustMaterialCertificates(timestamp)...)
	}

	for _, cert := range trustMaterialCertificates(material) {
		if !certificateSetContains(known, cert) {
			return true
		}
	}
	return false
}

func certificateSetContains(certs []*x509.Certificate, cert *x509.Certificate) bool {
	if cert == nil {
		return true
	}
	for _, existing := range certs {
		if existing != nil && bytes.Equal(existing.Raw, cert.Raw) {
			return true
		}
	}
	return false
}
