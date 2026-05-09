package validation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"signer-engine/internal/signature/cms"
)

type CRLTrustMaterialExtractor struct {
	CRLs       []*x509.RevocationList
	Issuers    []*x509.Certificate
	HTTPClient *http.Client
	CacheDir   string
	Now        func() time.Time
}

const defaultCRLCacheDir = "internal/validation/crl-cache"

func (p CRLTrustMaterialExtractor) FromCertificate(
	ctx context.Context,
	leaf *x509.Certificate,
	chain []*x509.Certificate,
) (*TrustMaterial, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if leaf == nil {
		return nil, errors.New("signing certificate is required")
	}

	slog.Info("validation: extracting trust material",
		"subject", leaf.Subject.String(),
		"provided_chain_certs", len(chain),
		"provided_issuers", len(p.Issuers),
		"provided_crls", len(p.CRLs),
	)

	chain = p.completeChain(ctx, leaf, chain)
	slog.Info("validation: certificate chain ready", "chain_certs", len(chain))

	crls, err := p.resolveRevocationLists(ctx, leaf, chain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve revocation data: %w", err)
	}

	return &TrustMaterial{
		Leaf:  leaf,
		Chain: chain,
		CRLs:  crls,
	}, nil
}

func (p CRLTrustMaterialExtractor) FromTimestampToken(ctx context.Context, tokenDER []byte) (*TrustMaterial, error) {
	leaf, chain, err := timestampTokenSignerChain(tokenDER)
	if err != nil {
		return nil, fmt.Errorf("failed to extract timestamp certificates: %w", err)
	}
	if leaf == nil {
		slog.Info("validation: timestamp token has no signer certificate info")
		return nil, nil
	}

	return p.FromCertificate(ctx, leaf, chain)
}

func (p CRLTrustMaterialExtractor) resolveRevocationLists(ctx context.Context, cert *x509.Certificate, chain []*x509.Certificate) ([]*x509.RevocationList, error) {
	issuerCerts := append([]*x509.Certificate(nil), chain...)
	issuerCerts = append(issuerCerts, p.Issuers...)

	targetCerts := append([]*x509.Certificate{cert}, chain...)
	resolvedCRLs := make([]*x509.RevocationList, 0, len(p.CRLs))
	seenCRLs := map[string]struct{}{}

	for _, target := range targetCerts {
		if target == nil {
			return nil, errors.New("certificate chain contains nil certificate")
		}

		slog.Info("validation: resolving CRL for certificate",
			"subject", target.Subject.String(),
			"distribution_points", len(target.CRLDistributionPoints),
		)
		crl, issuer, ok, err := p.crlForCertificate(ctx, target, issuerCerts)
		if err != nil {
			return nil, err
		}
		if !ok {
			slog.Info("validation: no CRL resolved for certificate", "subject", target.Subject.String())
			continue
		}
		if err := p.validateCRL(crl, issuer); err != nil {
			return nil, err
		}

		key := string(crl.Raw)
		if _, ok := seenCRLs[key]; ok {
			slog.Info("validation: CRL already referenced", "issuer", issuer.Subject.String())
			continue
		}
		seenCRLs[key] = struct{}{}
		resolvedCRLs = append(resolvedCRLs, crl)
	}

	if len(resolvedCRLs) == 0 {
		return nil, errors.New("no matching CRL found for certificate chain")
	}

	return resolvedCRLs, nil
}

func (p CRLTrustMaterialExtractor) crlForCertificate(ctx context.Context, target *x509.Certificate, issuers []*x509.Certificate) (*x509.RevocationList, *x509.Certificate, bool, error) {
	crl, issuer, ok := findProvidedCRLForCertificate(target, p.CRLs, issuers)
	if ok {
		slog.Info("validation: using provided CRL",
			"subject", target.Subject.String(),
			"issuer", issuer.Subject.String(),
		)
		return crl, issuer, true, nil
	}

	issuer, ok = findIssuerForCertificate(target, issuers)
	if !ok {
		slog.Info("validation: issuer certificate not found", "subject", target.Subject.String())
		return nil, nil, false, nil
	}

	crl, err := p.fetchCRL(ctx, target, issuer)
	if err != nil {
		return nil, nil, false, err
	}
	if crl == nil {
		return nil, nil, false, nil
	}

	return crl, issuer, true, nil
}

func findProvidedCRLForCertificate(target *x509.Certificate, crls []*x509.RevocationList, issuers []*x509.Certificate) (*x509.RevocationList, *x509.Certificate, bool) {
	for _, issuer := range issuers {
		if issuer == nil || !bytes.Equal(issuer.RawSubject, target.RawIssuer) {
			continue
		}

		for _, crl := range crls {
			if crl != nil && bytes.Equal(crl.RawIssuer, issuer.RawSubject) {
				return crl, issuer, true
			}
		}
	}

	return nil, nil, false
}

func findIssuerForCertificate(target *x509.Certificate, issuers []*x509.Certificate) (*x509.Certificate, bool) {
	for _, issuer := range issuers {
		if issuer != nil && bytes.Equal(issuer.RawSubject, target.RawIssuer) {
			return issuer, true
		}
	}
	return nil, false
}

func (p CRLTrustMaterialExtractor) completeChain(ctx context.Context, cert *x509.Certificate, chain []*x509.Certificate) []*x509.Certificate {
	completed := appendCertificateSet(nil, chain...)
	issuers := appendCertificateSet(completed, p.Issuers...)
	current := cert

	if len(chain) > 0 {
		slog.Info("validation: using certificates extracted from credential chain", "chain_certs", len(chain))
	}

	for depth := 0; depth < 5 && current != nil; depth++ {
		if issuer, ok := findIssuerForCertificate(current, issuers); ok {
			slog.Info("validation: issuer found in available certificates",
				"subject", current.Subject.String(),
				"issuer", issuer.Subject.String(),
				"depth", depth,
			)
			if bytes.Equal(issuer.RawSubject, issuer.RawIssuer) {
				break
			}
			current = issuer
			continue
		}

		fetched, err := p.fetchIssuerCertificates(ctx, current)
		if err != nil || len(fetched) == 0 {
			if err != nil {
				slog.Info("validation: failed to fetch issuer certificates via AIA",
					"subject", current.Subject.String(),
					"error", err.Error(),
				)
			} else {
				slog.Info("validation: no issuer certificates fetched via AIA", "subject", current.Subject.String())
			}
			break
		}
		slog.Info("validation: issuer certificates fetched via AIA",
			"subject", current.Subject.String(),
			"count", len(fetched),
		)

		var next *x509.Certificate
		for _, issuer := range fetched {
			if issuer == nil || !issuer.IsCA {
				continue
			}
			completed = appendCertificateSet(completed, issuer)
			issuers = appendCertificateSet(issuers, issuer)
			if next == nil && bytes.Equal(issuer.RawSubject, current.RawIssuer) {
				next = issuer
			}
		}
		if next == nil || bytes.Equal(next.RawSubject, next.RawIssuer) {
			break
		}
		current = next
	}

	return completed
}

func (p CRLTrustMaterialExtractor) fetchIssuerCertificates(ctx context.Context, cert *x509.Certificate) ([]*x509.Certificate, error) {
	if len(cert.IssuingCertificateURL) == 0 {
		slog.Info("validation: certificate has no AIA issuer URL", "subject", cert.Subject.String())
		return nil, nil
	}

	var lastErr error
	for _, uri := range cert.IssuingCertificateURL {
		slog.Info("validation: fetching issuer certificates from AIA", "uri", uri)
		certs, err := p.fetchCertificatesFromURI(ctx, uri)
		if err == nil && len(certs) > 0 {
			slog.Info("validation: issuer certificates downloaded from AIA", "uri", uri, "count", len(certs))
			return certs, nil
		}
		if err != nil {
			slog.Info("validation: issuer certificate AIA fetch failed", "uri", uri, "error", err.Error())
		}
		lastErr = err
	}
	return nil, lastErr
}

func (p CRLTrustMaterialExtractor) fetchCertificatesFromURI(ctx context.Context, uri string) ([]*x509.Certificate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build issuer certificate request for %q: %w", uri, err)
	}

	client := p.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch issuer certificates %q: %w", uri, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("failed to fetch issuer certificates %q: unexpected status %s", uri, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read issuer certificates %q: %w", uri, err)
	}

	certs, err := parseCertificates(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer certificates %q: %w", uri, err)
	}
	slog.Info("validation: issuer certificates parsed", "uri", uri, "count", len(certs), "bytes", len(body))

	return certs, nil
}

func (p CRLTrustMaterialExtractor) fetchCRL(ctx context.Context, cert *x509.Certificate, issuer *x509.Certificate) (*x509.RevocationList, error) {
	var lastErr error
	for _, uri := range cert.CRLDistributionPoints {
		if crl, ok := p.cachedCRL(uri, issuer); ok {
			slog.Info("validation: using cached CRL", "uri", uri, "issuer", issuer.Subject.String())
			return crl, nil
		}

		slog.Info("validation: fetching CRL", "uri", uri, "issuer", issuer.Subject.String())
		crl, err := p.fetchCRLFromURI(ctx, uri)
		if err == nil {
			if err := p.validateCRL(crl, issuer); err != nil {
				lastErr = err
				continue
			}
			p.cacheCRL(uri, crl.Raw)
			return crl, nil
		}
		slog.Info("validation: CRL fetch failed", "uri", uri, "error", err.Error())
		lastErr = err
	}
	return nil, lastErr
}

func (p CRLTrustMaterialExtractor) cachedCRL(uri string, issuer *x509.Certificate) (*x509.RevocationList, bool) {
	path := p.cachePath(uri)

	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Info("validation: CRL cache read failed", "uri", uri, "path", path, "error", err.Error())
		}
		return nil, false
	}

	crl, err := parseCRL(data)
	if err != nil {
		_ = os.Remove(path)
		slog.Info("validation: removed invalid CRL cache entry", "uri", uri, "path", path)
		return nil, false
	}

	if err := p.validateCRL(crl, issuer); err != nil {
		_ = os.Remove(path)
		slog.Info("validation: removed stale CRL cache entry", "uri", uri, "path", path, "error", err.Error())
		return nil, false
	}

	return crl, true
}

func (p CRLTrustMaterialExtractor) cacheCRL(uri string, der []byte) {
	if len(der) == 0 {
		return
	}

	path := p.cachePath(uri)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		slog.Info("validation: failed to create CRL cache directory", "uri", uri, "path", path, "error", err.Error())
		return
	}
	if err := os.WriteFile(path, der, 0o644); err != nil {
		slog.Info("validation: failed to add CRL to cache", "uri", uri, "path", path, "error", err.Error())
		return
	}
	slog.Info("validation: added CRL to cache", "uri", uri, "path", path, "bytes", len(der))
}

func (p CRLTrustMaterialExtractor) cachePath(uri string) string {
	sum := sha256.Sum256([]byte(uri))
	return filepath.Join(p.cacheDir(), hex.EncodeToString(sum[:])+".crl")
}

func (p CRLTrustMaterialExtractor) cacheDir() string {
	if p.CacheDir != "" {
		return p.CacheDir
	}
	return defaultCRLCacheDir
}

func (p CRLTrustMaterialExtractor) validateCRL(crl *x509.RevocationList, issuer *x509.Certificate) error {
	if crl == nil {
		return errors.New("CRL is required")
	}
	if issuer == nil {
		return errors.New("CRL issuer is required")
	}

	now := p.now()
	if crl.ThisUpdate.After(now) {
		return fmt.Errorf("CRL thisUpdate is in the future: %s", crl.ThisUpdate.UTC().Format(time.RFC3339))
	}
	if crl.NextUpdate.IsZero() {
		return errors.New("CRL nextUpdate is required")
	}
	if !crl.NextUpdate.After(now) {
		return fmt.Errorf("CRL expired at %s", crl.NextUpdate.UTC().Format(time.RFC3339))
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("failed to verify CRL signature for issuer %s: %w", issuer.Subject.String(), err)
	}

	return nil
}

func (p CRLTrustMaterialExtractor) now() time.Time {
	if p.Now != nil {
		return p.Now().UTC()
	}
	return time.Now().UTC()
}

func (p CRLTrustMaterialExtractor) fetchCRLFromURI(ctx context.Context, uri string) (*x509.RevocationList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build CRL request for %q: %w", uri, err)
	}

	client := p.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CRL %q: %w", uri, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("failed to fetch CRL %q: unexpected status %s", uri, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read CRL %q: %w", uri, err)
	}

	crl, err := parseCRL(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL %q: %w", uri, err)
	}
	slog.Info("validation: CRL downloaded", "uri", uri, "bytes", len(body))

	return crl, nil
}

func parseCRL(data []byte) (*x509.RevocationList, error) {
	if block, _ := pem.Decode(data); block != nil {
		return x509.ParseRevocationList(block.Bytes)
	}
	return x509.ParseRevocationList(data)
}

func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) > 0 {
		return certs, nil
	}

	if cert, err := x509.ParseCertificate(data); err == nil {
		return []*x509.Certificate{cert}, nil
	}

	var contentInfo cms.ContentInfo
	if _, err := asn1.Unmarshal(data, &contentInfo); err == nil && contentInfo.ContentType.Equal(cms.OIDSignedData) {
		var signedData cms.SignedData
		if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signedData); err == nil {
			for _, raw := range signedData.Certificates {
				cert, err := x509.ParseCertificate(raw.FullBytes)
				if err != nil {
					continue
				}
				certs = append(certs, cert)
			}
			if len(certs) > 0 {
				return certs, nil
			}
		}
	}

	return x509.ParseCertificates(data)
}

func appendCertificateSet(base []*x509.Certificate, extra ...*x509.Certificate) []*x509.Certificate {
	out := append([]*x509.Certificate(nil), base...)
	for _, cert := range extra {
		if cert == nil {
			continue
		}

		var exists bool
		for _, existing := range out {
			if existing != nil && bytes.Equal(existing.Raw, cert.Raw) {
				exists = true
				break
			}
		}
		if !exists {
			out = append(out, cert)
		}
	}
	return out
}
