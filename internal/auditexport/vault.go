package auditexport

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

var vaultName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type VaultTransitSigner struct {
	baseURL    *url.URL
	tokenFile  string
	namespace  string
	mount      string
	key        string
	managedKey string
	client     *http.Client
}

func NewVaultTransitSigner(rawURL, tokenFile, namespace, mount, key, managedKey string, client *http.Client) (*VaultTransitSigner, error) {
	base, err := url.Parse(rawURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil ||
		base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("audit export: Vault endpoint must use HTTPS")
	}
	if tokenFile == "" {
		return nil, errors.New("audit export: Vault Agent token file is required")
	}
	if mount == "" {
		mount = "transit"
	}
	if !vaultName.MatchString(mount) || !vaultName.MatchString(key) ||
		!vaultName.MatchString(managedKey) {
		return nil, errors.New("audit export: invalid Vault mount, Transit key, or HSM managed-key name")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &VaultTransitSigner{
		baseURL: base, tokenFile: tokenFile, namespace: namespace,
		mount: mount, key: key, managedKey: managedKey, client: client,
	}, nil
}

func (v *VaultTransitSigner) Sign(ctx context.Context, keyID string, payload []byte) ([]byte, error) {
	if keyID != v.key || len(payload) == 0 {
		return nil, errors.New("audit export: unbound Vault signing request")
	}
	var response struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	err := v.call(ctx, http.MethodPost, "sign/"+keyID, map[string]any{
		"input":          base64.StdEncoding.EncodeToString(payload),
		"hash_algorithm": "sha2-256",
		"prehashed":      false,
	}, &response)
	if err != nil {
		return nil, fmt.Errorf("audit export: Vault sign: %w", err)
	}
	if !strings.HasPrefix(response.Data.Signature, "vault:v") || len(response.Data.Signature) > 16<<10 {
		return nil, errors.New("audit export: Vault returned malformed signature")
	}
	return []byte(response.Data.Signature), nil
}

func (v *VaultTransitSigner) Verify(ctx context.Context, keyID string, payload, signature []byte) error {
	if keyID != v.key || len(payload) == 0 || len(signature) == 0 || len(signature) > 16<<10 {
		return errors.New("audit export: unbound Vault verification request")
	}
	var response struct {
		Data struct {
			Valid bool `json:"valid"`
		} `json:"data"`
	}
	err := v.call(ctx, http.MethodPost, "verify/"+keyID, map[string]any{
		"input":          base64.StdEncoding.EncodeToString(payload),
		"signature":      string(signature),
		"hash_algorithm": "sha2-256",
		"prehashed":      false,
	}, &response)
	if err != nil {
		return fmt.Errorf("audit export: Vault verify: %w", err)
	}
	if !response.Data.Valid {
		return errors.New("audit export: Vault rejected checkpoint signature")
	}
	return nil
}

// Health proves the exact key is readable, non-exportable, non-deletable, and
// that both HSM-backed sign and verify capabilities work with the current
// short-lived Vault Agent token. It never falls back to process-local keys.
func (v *VaultTransitSigner) Health(ctx context.Context) error {
	var keyResponse struct {
		Data struct {
			Type                 string `json:"type"`
			Exportable           bool   `json:"exportable"`
			AllowPlaintextBackup bool   `json:"allow_plaintext_backup"`
			DeletionAllowed      bool   `json:"deletion_allowed"`
			SupportsSigning      bool   `json:"supports_signing"`
		} `json:"data"`
	}
	if err := v.call(ctx, http.MethodGet, "keys/"+v.key, nil, &keyResponse); err != nil {
		return fmt.Errorf("audit export: inspect Vault signing key: %w", err)
	}
	if keyResponse.Data.Type != "managed_key" || !keyResponse.Data.SupportsSigning ||
		keyResponse.Data.Exportable ||
		keyResponse.Data.AllowPlaintextBackup || keyResponse.Data.DeletionAllowed {
		return errors.New("audit export: Vault signing key is not a signing-capable non-exportable managed key")
	}
	var managedResponse struct {
		Data struct {
			Name            string `json:"name"`
			Type            string `json:"type"`
			AllowReplaceKey bool   `json:"allow_replace_key"`
		} `json:"data"`
	}
	if err := v.callAPI(ctx, http.MethodGet,
		"sys/managed-keys/pkcs11/"+v.managedKey, nil, &managedResponse); err != nil {
		return fmt.Errorf("audit export: inspect PKCS#11 managed key: %w", err)
	}
	if managedResponse.Data.Name != v.managedKey || managedResponse.Data.Type != "pkcs11" ||
		managedResponse.Data.AllowReplaceKey {
		return errors.New("audit export: managed key is not the pinned non-replaceable PKCS#11 HSM key")
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return fmt.Errorf("audit export: health challenge entropy: %w", err)
	}
	signature, err := v.Sign(ctx, v.key, challenge)
	if err != nil {
		return err
	}
	return v.Verify(ctx, v.key, challenge, signature)
}

func (v *VaultTransitSigner) call(ctx context.Context, method, operation string, body any, output any) error {
	return v.callAPI(ctx, method, path.Join(v.mount, operation), body, output)
}

func (v *VaultTransitSigner) callAPI(ctx context.Context, method, apiPath string, body any, output any) error {
	token, err := readVaultAgentToken(v.tokenFile)
	if err != nil {
		return err
	}
	endpoint := *v.baseURL
	endpoint.Path = path.Join(strings.TrimRight(endpoint.Path, "/"), "v1", apiPath)
	var input io.Reader
	if body != nil {
		encoded, encodeErr := json.Marshal(body)
		if encodeErr != nil {
			return encodeErr
		}
		input = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), input)
	if err != nil {
		return err
	}
	request.Header.Set("X-Vault-Token", token)
	if v.namespace != "" {
		request.Header.Set("X-Vault-Namespace", v.namespace)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := v.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		// Never reflect a Vault body: plugins can include operational secrets in
		// errors. Status is sufficient for bounded telemetry.
		return fmt.Errorf("Vault request failed: status=%d", response.StatusCode)
	}
	if output != nil {
		if err := json.Unmarshal(raw, output); err != nil {
			return fmt.Errorf("decode Vault response: %w", err)
		}
	}
	return nil
}

func readVaultAgentToken(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", fmt.Errorf("audit export: read Vault Agent token: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("audit export: inspect Vault Agent token: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0007 != 0 {
		return "", errors.New("audit export: Vault Agent token must be a non-world-accessible regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, (16<<10)+1))
	if err != nil {
		return "", fmt.Errorf("audit export: read Vault Agent token: %w", err)
	}
	if len(raw) > 16<<10 {
		return "", errors.New("audit export: Vault Agent token is oversized")
	}
	token := strings.TrimSpace(string(raw))
	if token == "" || strings.ContainsAny(token, "\r\n\x00") {
		return "", errors.New("audit export: Vault Agent token is empty or malformed")
	}
	return token, nil
}
