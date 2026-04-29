// icpbrasil/base.go (novo)
package icpbrasil

import (
	"crypto"
	"crypto/x509"
	"embed"
	"encoding/asn1"
	"errors"
	"fmt"
	"sync"
)

//go:embed roots/*.crt
var icpBrasilRootFS embed.FS

var (
	icpBrasilRootsOnce sync.Once
	icpBrasilRoots     *x509.CertPool
	icpBrasilRootsErr  error
)

type icpBrasilBase struct {
	rootPool func() (*x509.CertPool, error)
}

func (p icpBrasilBase) ValidateSigningCertificate(cert *x509.Certificate, chain []*x509.Certificate) error {
	if cert == nil {
		return errors.New("certificate is required")
	}

	// DOC-ICP-04.01 Versão 5.0
	if !subjectHasOID(cert, oidSubjectCPF) &&
		!subjectHasOID(cert, oidSubjectCNPJ) {
		return errors.New("certificate subject does not contain CPF or CNPJ")
	}

	// DOC-ICP-04.01 Versão 5.0
	if !hasPolicyWithPrefix(cert, oidCertificatePolicyICPBRasilPrefix) {
		return errors.New("certificate policies extension does not contain ICP-Brasil prefix")
	}

	rootPool := p.rootPool
	if rootPool == nil {
		rootPool = icpBrasilRootPool
	}

	roots, err := rootPool()
	if err != nil {
		return fmt.Errorf("failed to get icp brasil root pool: %w", err)
	}

	if err := validateChain(cert, chain, roots); err != nil {
		return fmt.Errorf("failed to validate chain: %w", err)
	}

	return nil
}

func (icpBrasilBase) MandatedHashAlg() crypto.Hash {
	return crypto.SHA256
}

func icpBrasilRootPool() (*x509.CertPool, error) {
	icpBrasilRootsOnce.Do(func() {
		icpBrasilRoots = x509.NewCertPool()

		entries, err := icpBrasilRootFS.ReadDir("roots")
		if err != nil {
			icpBrasilRootsErr = fmt.Errorf("failed to read icp-brasil-certs-root directory: %w", err)
			return
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			pemBytes, err := icpBrasilRootFS.ReadFile("roots/" + entry.Name())
			if err != nil {
				icpBrasilRootsErr = fmt.Errorf("failed to read %s: %w", entry.Name(), err)
				return
			}

			if ok := icpBrasilRoots.AppendCertsFromPEM(pemBytes); !ok {
				icpBrasilRootsErr = fmt.Errorf("failed to append certificate from %s", entry.Name())
				return
			}
		}
	})

	return icpBrasilRoots, icpBrasilRootsErr
}

func validateChain(cert *x509.Certificate, chain []*x509.Certificate, roots *x509.CertPool) error {
	intermediates := x509.NewCertPool()

	for _, intermediate := range chain {
		if intermediate == nil {
			continue
		}

		intermediates.AddCert(intermediate)
	}

	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("certificate key usage does not allow digital signature")
	}

	_, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})

	return err
}

func subjectHasOID(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, name := range cert.Subject.Names {
		if name.Type.Equal(oid) {
			return true
		}
	}

	for _, name := range cert.Subject.ExtraNames {
		if name.Type.Equal(oid) {
			return true
		}
	}

	return false
}

func hasPolicyWithPrefix(cert *x509.Certificate, prefix asn1.ObjectIdentifier) bool {
	for _, policy := range cert.PolicyIdentifiers {
		if oidHasPrefix(policy, prefix) {
			return true
		}
	}

	return false
}

func oidHasPrefix(oid, prefix asn1.ObjectIdentifier) bool {
	if len(oid) < len(prefix) {
		return false
	}

	for i := range prefix {
		if oid[i] != prefix[i] {
			return false
		}
	}

	return true
}
