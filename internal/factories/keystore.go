package factories

import (
	"errors"
	"signer-engine/internal/keystore"
	"signer-engine/internal/keystore/pkcs12"
)

type Type string

const (
	TypePKCS12 Type = "pkcs12"
)

type Config struct {
	Type   Type
	PKCS12 *pkcs12.Config
}

func NewStore(cfg Config) (keystore.Store, error) {
	switch cfg.Type {
	case TypePKCS12:
		if cfg.PKCS12 == nil {
			return nil, errors.New("pkcs12 configuration is required")
		}
		return pkcs12.NewStore(*cfg.PKCS12), nil
	default:
		return nil, errors.New("invalid keystore type")
	}
}
