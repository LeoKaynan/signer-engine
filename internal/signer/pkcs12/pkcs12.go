package pkcs12

import (
	"crypto"
	"errors"
	"fmt"
	"os"
	"signer-engine/internal/signer"

	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

func NewCredentialFromFile(path, password string) (signer.Credential, error) {
	if path == "" {
		return nil, errors.New("path is required")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return NewCredentialFromBytes(data, password)
}

func NewCredentialFromBytes(data []byte, password string) (signer.Credential, error) {
	privateKey, certificate, chain, err := gopkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, fmt.Errorf("failed to decode chain: %w", err)
	}

	privateKeySigner, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key is not a crypto.Signer")
	}

	return newCredential(privateKeySigner, certificate, chain), nil
}
