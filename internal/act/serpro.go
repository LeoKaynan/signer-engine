package act

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var _ Provider = (*SerproClient)(nil)

const (
	timestampQueryContentType = "application/timestamp-query"
	defaultHTTPTimeout        = 30 * time.Second
)

type SerproConfig struct {
	TokenURL     string
	StampURL     string
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
}

type SerproClient struct {
	tokenURL     string
	stampURL     string
	clientID     string
	clientSecret string
	httpClient   *http.Client

	mu          sync.Mutex
	accessToken string
	expiresAt   time.Time
}

func NewSerproClient(config SerproConfig) *SerproClient {
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}

	return &SerproClient{
		tokenURL:     config.TokenURL,
		stampURL:     config.StampURL,
		clientID:     config.ClientID,
		clientSecret: config.ClientSecret,
		httpClient:   httpClient,
	}
}

func (c *SerproClient) Stamp(ctx context.Context, input []byte, hashAlg crypto.Hash) (*TimestampToken, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}

	accessToken, err := c.accessTokenValue(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get serpro access token: %w", err)
	}

	requestDER, err := BuildRequest(input, hashAlg)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.stampURL, bytes.NewReader(requestDER))
	if err != nil {
		return nil, fmt.Errorf("failed to create timestamp request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", timestampQueryContentType)
	req.Header.Set("Accept", "application/timestamp-reply, application/timestamp-token, application/octet-stream, application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call serpro timestamp endpoint: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read serpro timestamp response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("serpro timestamp endpoint returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	tokenDER, err := decodeTimestampResponse(body, resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}

	return &TimestampToken{TokenDER: tokenDER}, nil
}

func (c *SerproClient) validate() error {
	if strings.TrimSpace(c.tokenURL) == "" {
		return errors.New("serpro token URL is required")
	}
	if strings.TrimSpace(c.stampURL) == "" {
		return errors.New("serpro timestamp URL is required")
	}
	if strings.TrimSpace(c.clientID) == "" {
		return errors.New("serpro client ID is required")
	}
	if strings.TrimSpace(c.clientSecret) == "" {
		return errors.New("serpro client secret is required")
	}
	return nil
}

func (c *SerproClient) accessTokenValue(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.accessToken != "" && time.Now().Before(c.expiresAt.Add(-30*time.Second)) {
		return c.accessToken, nil
	}

	values := url.Values{}
	values.Set("grant_type", "client_credentials")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(values.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.SetBasicAuth(c.clientID, c.clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call serpro token endpoint: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read serpro token response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("serpro token endpoint returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("failed to parse serpro token response: %w", err)
	}
	if payload.AccessToken == "" {
		return "", errors.New("serpro token response did not include access_token")
	}

	expiresIn := payload.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 300
	}

	c.accessToken = payload.AccessToken
	c.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)

	return c.accessToken, nil
}

func decodeTimestampResponse(body []byte, contentType string) ([]byte, error) {
	if strings.Contains(strings.ToLower(contentType), "json") {
		var payload map[string]string
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, fmt.Errorf("failed to parse timestamp JSON response: %w", err)
		}

		for _, key := range []string{"token", "stamp", "timestampToken", "timeStampToken"} {
			if value := payload[key]; value != "" {
				decoded, err := base64.StdEncoding.DecodeString(value)
				if err != nil {
					return nil, fmt.Errorf("failed to decode timestamp token from %q: %w", key, err)
				}
				return ExtractToken(decoded)
			}
		}

		return nil, errors.New("timestamp JSON response did not include a token field")
	}

	return ExtractToken(body)
}
