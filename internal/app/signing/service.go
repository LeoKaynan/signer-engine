package signing

import (
	"crypto"
	"fmt"
	"log/slog"
	"os"
	"signer-engine/internal/signature/cades"
	"signer-engine/internal/signature/icpbrasil"
	"signer-engine/internal/signer"
	"signer-engine/internal/tsa"
	"signer-engine/internal/validation"
)

type Service struct {
	TimeStampProvider      tsa.Provider
	TrustMaterialExtractor validation.TrustMaterialExtractor
}

func NewFromEnv() Service {
	return Service{
		TimeStampProvider: tsa.NewSerproClient(tsa.SerproConfig{
			TokenURL:     os.Getenv("SERPRO_ACT_TOKEN_URL"),
			StampURL:     os.Getenv("SERPRO_ACT_STAMP_URL"),
			ClientID:     os.Getenv("SERPRO_ACT_CLIENT_ID"),
			ClientSecret: os.Getenv("SERPRO_ACT_CLIENT_SECRET"),
		}),
		TrustMaterialExtractor: validation.CRLTrustMaterialExtractor{},
	}
}

func (s Service) Sign(request Request) (Response, error) {
	slog.Info("signing: starting",
		"format", request.Format,
		"policy", request.Policy,
		"mode", request.Mode,
		"data_bytes", len(request.Data),
	)

	credential, err := credentialResolver(request)
	if err != nil {
		return Response{}, fmt.Errorf("failed to resolve credential: %w", err)
	}
	slog.Info("signing: credential resolved", "provider", request.CredentialProvider)

	switch request.Format {
	case FormatCades:
		return s.signCades(request, credential)
	default:
		return Response{}, fmt.Errorf("unsupported format: %s", request.Format)
	}
}

func (s Service) signCades(request Request, credential signer.Credential) (Response, error) {
	detached, err := cadesModeResolver(request.Mode)
	if err != nil {
		return Response{}, fmt.Errorf("failed to resolve mode: %w", err)
	}
	slog.Info("signing: CAdES mode resolved", "detached", detached)

	policy, err := icpbrasil.NewPolicy(request.Policy)
	if err != nil {
		return Response{}, fmt.Errorf("failed to resolve policy: %w", err)
	}
	slog.Info("signing: policy resolved", "name", request.Policy, "oid", policy.Identifier())

	signer := cades.Signer{
		Credential:             credential,
		Policy:                 policy,
		Detached:               detached,
		HashAlg:                crypto.SHA256,
		TimeStampProvider:      s.TimeStampProvider,
		TrustMaterialExtractor: s.TrustMaterialExtractor,
	}

	signature, err := signer.Sign(request.Data)
	if err != nil {
		return Response{}, fmt.Errorf("failed to sign: %w", err)
	}
	slog.Info("signing: signature completed", "bytes", len(signature))

	return Response{Signature: signature}, nil
}
