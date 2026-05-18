package signing

import (
	"crypto"
	"fmt"
	"io"
	"net/http"
	"time"

	"signer-engine/internal/signature/cades"
	"signer-engine/internal/signature/icpbrasil"
	"signer-engine/internal/signature/pades"
	"signer-engine/internal/signature/signaturepolicy"
	"signer-engine/internal/signer"
	"signer-engine/internal/signer/pkcs12"
)

var pbadHTTPClient = &http.Client{Timeout: 30 * time.Second}

// CAdESPolicyResolver resolves a CAdES policy by name. Service.NewFromEnv
// installs icpbrasil.NewCAdESPolicy as the default — override the field for
// tests or alternative policy sets.
type CAdESPolicyResolver func(signaturepolicy.PolicyName) (cades.Policy, error)

// PAdESPolicyResolver resolves a PAdES policy by name.
type PAdESPolicyResolver func(signaturepolicy.PolicyName) (pades.Policy, error)

// NewCAdESSignerFactory returns a SignerFactory that builds a cades.Signer
// using the given policy resolver. A nil resolver falls back to ICP-Brasil.
func NewCAdESSignerFactory(resolver CAdESPolicyResolver) SignerFactory {
	if resolver == nil {
		resolver = icpbrasil.NewCAdESPolicy
	}
	return func(deps SignerDeps, credential signer.Credential, request Request) (signaturepolicy.Signer, error) {
		detached, err := cadesModeIsDetached(request.Mode)
		if err != nil {
			return nil, fmt.Errorf("resolve mode: %w", err)
		}
		policy, err := resolver(request.Policy)
		if err != nil {
			return nil, fmt.Errorf("resolve CAdES policy: %w", err)
		}
		logPolicyResolved(request.Policy, policy)
		return &cades.Signer{
			Credential:             credential,
			Policy:                 policy,
			Detached:               detached,
			HashAlg:                crypto.SHA256,
			TimeStampProvider:      deps.TimeStampProvider,
			TrustMaterialExtractor: deps.TrustMaterialExtractor,
			Clock:                  deps.Clock,
		}, nil
	}
}

// NewPAdESSignerFactory returns a SignerFactory that builds a pades.Signer
// using the given policy resolver. A nil resolver falls back to ICP-Brasil.
func NewPAdESSignerFactory(resolver PAdESPolicyResolver) SignerFactory {
	if resolver == nil {
		resolver = icpbrasil.NewPAdESPolicy
	}
	return func(deps SignerDeps, credential signer.Credential, request Request) (signaturepolicy.Signer, error) {
		policy, err := resolver(request.Policy)
		if err != nil {
			return nil, fmt.Errorf("resolve PAdES policy: %w", err)
		}
		logPolicyResolved(request.Policy, policy)
		pbad, err := resolvePBADArtifacts(policy)
		if err != nil {
			return nil, fmt.Errorf("resolve PBAD artifacts: %w", err)
		}
		return &pades.Signer{
			Credential:             credential,
			Policy:                 policy,
			HashAlg:                crypto.SHA256,
			TimeStampProvider:      deps.TimeStampProvider,
			TrustMaterialExtractor: deps.TrustMaterialExtractor,
			Clock:                  deps.Clock,
			PBADArtifacts:          pbad,
		}, nil
	}
}

// resolvePBADArtifacts fetches the policy artifact, LPA artifact and LPA
// signature required by the PAdES DSS at levels C and A. Returns nil for
// policies that do not require PBAD entries (B/T) or do not advertise URLs.
func resolvePBADArtifacts(policy pades.Policy) (*pades.PBADArtifacts, error) {
	if policy.Level() < signaturepolicy.LevelC {
		return nil, nil
	}
	src, ok := policy.(pades.PBADArtifactSource)
	if !ok {
		return nil, nil
	}
	policyURL, lpaURL, lpaSigURL := src.PBADArtifactURLs()
	if policyURL == "" || lpaURL == "" || lpaSigURL == "" {
		return nil, nil
	}
	policyBytes, err := fetchPBADBytes(policyURL)
	if err != nil {
		return nil, fmt.Errorf("policy artifact: %w", err)
	}
	lpaBytes, err := fetchPBADBytes(lpaURL)
	if err != nil {
		return nil, fmt.Errorf("lpa artifact: %w", err)
	}
	lpaSigBytes, err := fetchPBADBytes(lpaSigURL)
	if err != nil {
		return nil, fmt.Errorf("lpa signature: %w", err)
	}
	return &pades.PBADArtifacts{
		PolicyArtifact: policyBytes,
		LpaArtifact:    lpaBytes,
		LpaSignature:   lpaSigBytes,
	}, nil
}

func fetchPBADBytes(url string) ([]byte, error) {
	resp, err := pbadHTTPClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body %s: %w", url, err)
	}
	return body, nil
}

// NewPKCS12CredentialResolver returns the default PKCS#12/PFX resolver.
func NewPKCS12CredentialResolver() CredentialResolver {
	return func(request Request) (signer.Credential, error) {
		return pkcs12.NewCredentialFromBytes(request.PKCS12Data, request.PKCS12Pass)
	}
}
