package pkcs12

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"signer-engine/internal/keystore"

	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

var _ keystore.Store = (*Store)(nil)

type Config struct {
	Path     string
	Password string
}

type Store struct {
	cfg         Config
	privateKey  crypto.PrivateKey
	certificate *x509.Certificate
	chain       []*x509.Certificate
}

func NewStore(cfg Config) *Store {
	return &Store{cfg: cfg}
}

func (s *Store) Open(ctx context.Context) error {
	if s.cfg.Path == "" {
		return errors.New("path is required")
	}

	data, err := os.ReadFile(s.cfg.Path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	privateKey, certificate, chain, err := gopkcs12.DecodeChain(data, s.cfg.Password)
	if err != nil {
		return fmt.Errorf("failed to decode chain: %w", err)
	}

	if _, ok := privateKey.(crypto.Signer); !ok {
		return errors.New("private key is not a crypto.Signer")
	}

	s.privateKey = privateKey
	s.certificate = certificate
	s.chain = chain

	return nil
}

func (s *Store) GetSigner(ctx context.Context, alias string) (keystore.Signer, error) {
	if s.privateKey == nil {
		return nil, errors.New("store is not open")
	}

	return newSigner(s.privateKey.(crypto.Signer), s.certificate, s.chain), nil
}

func (s *Store) Close(ctx context.Context) error {
	s.privateKey = nil
	s.certificate = nil
	s.chain = nil
	return nil
}
