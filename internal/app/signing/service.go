package signing

import (
	"fmt"
	"log/slog"
	"os"

	"signer-engine/internal/signature/signaturepolicy"
	"signer-engine/internal/signer"
	"signer-engine/internal/tsa"
	"signer-engine/internal/validation"
)

// Service is the application-level signing facade. It holds:
//   - Deps: shared dependencies wired into every signer (TSP, trust extractor,
//     clock).
//   - SignerFactories: one entry per Format. Service.Sign uses the matching
//     factory to build the concrete signer.
//   - CredentialResolvers: one entry per CredentialProvider. Resolves credential
//     bytes from the Request into a signer.Credential.
//
// To add a new format or credential provider, register one more entry in the
// corresponding map — Service.Sign itself never changes.
type Service struct {
	Deps                SignerDeps
	SignerFactories     map[Format]SignerFactory
	CredentialResolvers map[CredentialProvider]CredentialResolver
}

// DefaultService returns a Service with the default SignerFactories (CAdES +
// PAdES with ICP-Brasil policies) and CredentialResolvers (PKCS#12) registered,
// but no Deps populated. Useful for tests and for callers that want to add
// their own dependencies on top of the default registry.
func DefaultService() Service {
	return Service{
		SignerFactories: map[Format]SignerFactory{
			FormatCades: NewCAdESSignerFactory(nil),
			FormatPades: NewPAdESSignerFactory(nil),
		},
		CredentialResolvers: map[CredentialProvider]CredentialResolver{
			CredentialProviderPKCS12: NewPKCS12CredentialResolver(),
		},
	}
}

// NewFromEnv wires the default production stack: SERPRO TSA from env vars,
// CRL-based trust extraction, CAdES + PAdES factories with ICP-Brasil policies,
// and the PKCS#12 credential resolver.
func NewFromEnv() Service {
	return Service{
		Deps: SignerDeps{
			TimeStampProvider: tsa.NewSerproClient(tsa.SerproConfig{
				TokenURL:     os.Getenv("SERPRO_ACT_TOKEN_URL"),
				StampURL:     os.Getenv("SERPRO_ACT_STAMP_URL"),
				ClientID:     os.Getenv("SERPRO_ACT_CLIENT_ID"),
				ClientSecret: os.Getenv("SERPRO_ACT_CLIENT_SECRET"),
			}),
			TrustMaterialExtractor: validation.CRLTrustMaterialExtractor{},
		},
		SignerFactories: map[Format]SignerFactory{
			FormatCades: NewCAdESSignerFactory(nil),
			FormatPades: NewPAdESSignerFactory(nil),
		},
		CredentialResolvers: map[CredentialProvider]CredentialResolver{
			CredentialProviderPKCS12: NewPKCS12CredentialResolver(),
		},
	}
}

// Sign resolves the credential, builds the signer for the requested format
// via the registered factory, and runs it once. Format-specific behavior
// (CAdES co-sign detection, PAdES serial detection) lives inside each Signer.
func (s Service) Sign(request Request) (Response, error) {
	slog.Info("signing: starting",
		"format", request.Format,
		"policy", request.Policy,
		"mode", request.Mode,
		"data_bytes", len(request.Data),
		"has_existing", len(request.ExistingSignature) > 0,
	)

	credential, err := s.resolveCredential(request)
	if err != nil {
		return Response{}, err
	}
	slog.Info("signing: credential resolved", "provider", request.CredentialProvider)

	factory, ok := s.SignerFactories[request.Format]
	if !ok {
		return Response{}, fmt.Errorf("unsupported format: %s", request.Format)
	}

	sgnr, err := factory(s.Deps, credential, request)
	if err != nil {
		return Response{}, err
	}

	signature, err := sgnr.Sign(signaturepolicy.SignInput{
		Data:              request.Data,
		ExistingSignature: request.ExistingSignature,
	})
	if err != nil {
		return Response{}, err
	}

	slog.Info("signing: signature completed", "format", request.Format, "bytes", len(signature))
	return Response{Signature: signature}, nil
}

func (s Service) resolveCredential(request Request) (signer.Credential, error) {
	resolver, ok := s.CredentialResolvers[request.CredentialProvider]
	if !ok {
		return nil, fmt.Errorf("unsupported credential provider: %s", request.CredentialProvider)
	}
	c, err := resolver(request)
	if err != nil {
		return nil, fmt.Errorf("resolve credential: %w", err)
	}
	return c, nil
}

func logPolicyResolved(name signaturepolicy.PolicyName, policy signaturepolicy.Policy) {
	slog.Info("signing: policy resolved", "name", name, "oid", policy.Identifier(), "level", policy.Level())
}
