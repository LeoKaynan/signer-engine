// icpbrasil/base.go (novo)
package icpbrasil

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"embed"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

//go:embed roots/*.crt
var icpBrasilRootFS embed.FS

var (
	icpBrasilRootsPEMOnce sync.Once
	icpBrasilRootsPEM     []byte
	icpBrasilRootsPEMErr  error
)

type icpBrasilBase struct {
	rootPEM       func() ([]byte, error)
	validateChain func(cert *x509.Certificate, chain []*x509.Certificate, rootsPEM []byte) error
}

func (p icpBrasilBase) ValidateSigningCertificate(cert *x509.Certificate, chain []*x509.Certificate) error {
	if cert == nil {
		return errors.New("certificate is required")
	}

	// DOC-ICP-04.01 Versão 5.0
	if !hasPolicyWithPrefix(cert, oidCertificatePolicyICPBRasilPrefix) {
		return errors.New("certificate policies extension does not contain ICP-Brasil prefix")
	}

	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("certificate key usage does not allow digital signature")
	}

	rootPEM := p.rootPEM
	if rootPEM == nil {
		rootPEM = icpBrasilRootPEM
	}

	rootsPEM, err := rootPEM()
	if err != nil {
		return fmt.Errorf("failed to get icp brasil roots: %w", err)
	}

	validateChain := p.validateChain
	if validateChain == nil {
		validateChain = validateChainWithOpenSSL
	}

	if err := validateChain(cert, chain, rootsPEM); err != nil {
		return fmt.Errorf("failed to validate chain: %w", err)
	}

	return nil
}

func (icpBrasilBase) MandatedHashAlg() crypto.Hash {
	return crypto.SHA256
}

func icpBrasilRootPEM() ([]byte, error) {
	icpBrasilRootsPEMOnce.Do(func() {
		entries, err := icpBrasilRootFS.ReadDir("roots")
		if err != nil {
			icpBrasilRootsPEMErr = fmt.Errorf("failed to read icp-brasil-certs-root directory: %w", err)
			return
		}

		var roots bytes.Buffer
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			pemBytes, err := icpBrasilRootFS.ReadFile("roots/" + entry.Name())
			if err != nil {
				icpBrasilRootsPEMErr = fmt.Errorf("failed to read %s: %w", entry.Name(), err)
				return
			}

			if !containsPEMCertificate(pemBytes) {
				icpBrasilRootsPEMErr = fmt.Errorf("failed to read certificate PEM from %s", entry.Name())
				return
			}

			roots.Write(pemBytes)
			if !bytes.HasSuffix(pemBytes, []byte("\n")) {
				roots.WriteByte('\n')
			}
		}

		icpBrasilRootsPEM = roots.Bytes()
	})

	return icpBrasilRootsPEM, icpBrasilRootsPEMErr
}

func containsPEMCertificate(data []byte) bool {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return false
		}
		if block.Type == "CERTIFICATE" {
			return true
		}
		data = rest
	}
}

func validateChainWithOpenSSL(cert *x509.Certificate, chain []*x509.Certificate, rootsPEM []byte) error {
	if len(rootsPEM) == 0 {
		return errors.New("root certificates are required")
	}

	dir, err := os.MkdirTemp("", "signer-engine-icpbrasil-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(dir)

	signerPath := filepath.Join(dir, "signer.pem")
	intermediatesPath := filepath.Join(dir, "intermediates.pem")
	rootsPath := filepath.Join(dir, "roots.pem")

	if err := os.WriteFile(signerPath, certificateToPEM(cert), 0o600); err != nil {
		return fmt.Errorf("failed to write signer certificate: %w", err)
	}

	intermediatesPEM := certificatesToPEM(chain)
	hasIntermediates := len(intermediatesPEM) > 0
	if hasIntermediates {
		if err := os.WriteFile(intermediatesPath, intermediatesPEM, 0o600); err != nil {
			return fmt.Errorf("failed to write intermediate certificates: %w", err)
		}
	}

	if err := os.WriteFile(rootsPath, rootsPEM, 0o600); err != nil {
		return fmt.Errorf("failed to write root certificates: %w", err)
	}

	args := []string{
		"verify",
		"-purpose", "any",
		"-CAfile", rootsPath,
	}
	if hasIntermediates {
		args = append(args, "-untrusted", intermediatesPath)
	}
	args = append(args, signerPath)

	cmd := exec.Command("openssl", args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return errors.New(message)
	}

	return nil
}

func certificatesToPEM(certs []*x509.Certificate) []byte {
	var out bytes.Buffer
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		out.Write(certificateToPEM(cert))
	}
	return out.Bytes()
}

func certificateToPEM(cert *x509.Certificate) []byte {
	if cert == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
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
