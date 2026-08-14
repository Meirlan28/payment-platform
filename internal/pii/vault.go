package pii

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var vaultKeyName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type KeyManager interface {
	Encrypt(ctx context.Context, keyName string, plaintext, associatedData []byte) (string, error)
	Decrypt(ctx context.Context, keyName, ciphertext string, associatedData []byte) ([]byte, error)
	DestroyKey(ctx context.Context, keyName string) error
}

// TransitClient is a production HashiCorp Vault Transit adapter. Tokens should
// be supplied through an injected workload secret and never logged.
type TransitClient struct {
	BaseURL    *url.URL
	Token      string
	Namespace  string
	Mount      string
	HTTPClient *http.Client
}

func NewTransitClient(rawURL, token, namespace, mount string, client *http.Client) (*TransitClient, error) {
	base, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse Vault URL: %w", err)
	}
	if base.Scheme != "https" {
		return nil, errors.New("Vault Transit requires HTTPS")
	}
	if token == "" {
		return nil, errors.New("Vault token is required")
	}
	if mount == "" {
		mount = "transit"
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &TransitClient{BaseURL: base, Token: token, Namespace: namespace, Mount: mount, HTTPClient: client}, nil
}

func (v *TransitClient) Encrypt(ctx context.Context, keyName string, plaintext, associatedData []byte) (string, error) {
	if !vaultKeyName.MatchString(keyName) || len(plaintext) == 0 {
		return "", errors.New("invalid Transit key name or empty plaintext")
	}
	if err := v.call(ctx, http.MethodPost, "keys/"+keyName, map[string]any{
		"type": "aes256-gcm96", "derived": true,
		"exportable": false, "allow_plaintext_backup": false,
	}, nil); err != nil {
		return "", fmt.Errorf("ensure non-exportable Transit key: %w", err)
	}
	payload := map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plaintext)}
	if len(associatedData) != 0 {
		payload["context"] = base64.StdEncoding.EncodeToString(associatedData)
	}
	var response struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	if err := v.call(ctx, http.MethodPost, "encrypt/"+keyName, payload, &response); err != nil {
		return "", err
	}
	if response.Data.Ciphertext == "" {
		return "", errors.New("Vault returned an empty ciphertext")
	}
	return response.Data.Ciphertext, nil
}

func (v *TransitClient) Decrypt(ctx context.Context, keyName, ciphertext string, associatedData []byte) ([]byte, error) {
	if !vaultKeyName.MatchString(keyName) || ciphertext == "" {
		return nil, errors.New("invalid Transit key name or empty ciphertext")
	}
	payload := map[string]string{"ciphertext": ciphertext}
	if len(associatedData) != 0 {
		payload["context"] = base64.StdEncoding.EncodeToString(associatedData)
	}
	var response struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if err := v.call(ctx, http.MethodPost, "decrypt/"+keyName, payload, &response); err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(response.Data.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("decode Vault plaintext: %w", err)
	}
	return decoded, nil
}

func (v *TransitClient) DestroyKey(ctx context.Context, keyName string) error {
	if !vaultKeyName.MatchString(keyName) {
		return errors.New("invalid Transit key name")
	}
	// Vault deliberately requires deletion_allowed before destroying key material.
	if err := v.call(ctx, http.MethodPost, "keys/"+keyName+"/config", map[string]bool{"deletion_allowed": true}, nil); err != nil {
		return fmt.Errorf("allow Transit key deletion: %w", err)
	}
	if err := v.call(ctx, http.MethodDelete, "keys/"+keyName, nil, nil); err != nil {
		// A retry after a crash may observe an already deleted key.
		if strings.Contains(err.Error(), "status=404") {
			return nil
		}
		return fmt.Errorf("destroy Transit key: %w", err)
	}
	return nil
}

func (v *TransitClient) call(ctx context.Context, method, path string, body any, out any) error {
	endpoint := *v.BaseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/v1/" + strings.Trim(v.Mount, "/") + "/" + path
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), reader)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", v.Token)
	if v.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.Namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := v.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Vault error bodies are intentionally not propagated: an upstream
		// plugin must not be able to reflect key/plaintext material into logs.
		return fmt.Errorf("Vault request failed: status=%d", resp.StatusCode)
	}
	if out != nil && len(data) != 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode Vault response: %w", err)
		}
	}
	return nil
}
