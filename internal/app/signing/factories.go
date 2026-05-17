package signing

import (
	"crypto"
	"fmt"

	"signer-engine/internal/signature/cades"
	"signer-engine/internal/signature/icpbrasil"
	"signer-engine/internal/signature/pades"
	"signer-engine/internal/signature/signaturepolicy"
	"signer-engine/internal/signer"
	"signer-engine/internal/signer/pkcs12"
)

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
		return &pades.Signer{
			Credential:             credential,
			Policy:                 policy,
			HashAlg:                crypto.SHA256,
			TimeStampProvider:      deps.TimeStampProvider,
			TrustMaterialExtractor: deps.TrustMaterialExtractor,
			Clock:                  deps.Clock,
		}, nil
	}
}

// NewPKCS12CredentialResolver returns the default PKCS#12/PFX resolver.
func NewPKCS12CredentialResolver() CredentialResolver {
	return func(request Request) (signer.Credential, error) {
		return pkcs12.NewCredentialFromBytes(request.PKCS12Data, request.PKCS12Pass)
	}
}
