package auditexport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestVaultTransitSignerUsesRotatedAgentTokenAndNoLocalKey(t *testing.T) {
	var mu sync.Mutex
	var observedTokens []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		mu.Lock()
		observedTokens = append(observedTokens, request.Header.Get("X-Vault-Token"))
		mu.Unlock()
		switch request.URL.Path {
		case "/v1/transit/keys/audit-checkpoint":
			_ = json.NewEncoder(response).Encode(map[string]any{"data": map[string]any{
				"type": "managed_key", "exportable": false,
				"allow_plaintext_backup": false, "deletion_allowed": false,
				"supports_signing": true,
			}})
		case "/v1/sys/managed-keys/pkcs11/audit-checkpoint-hsm":
			_ = json.NewEncoder(response).Encode(map[string]any{"data": map[string]any{
				"name": "audit-checkpoint-hsm", "type": "pkcs11", "allow_replace_key": false,
			}})
		case "/v1/transit/sign/audit-checkpoint":
			_ = json.NewEncoder(response).Encode(map[string]any{"data": map[string]any{"signature": "vault:v7:c2lnbmF0dXJl"}})
		case "/v1/transit/verify/audit-checkpoint":
			_ = json.NewEncoder(response).Encode(map[string]any{"data": map[string]any{"valid": true}})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	tokenFile := filepath.Join(t.TempDir(), "agent-token")
	if err := os.WriteFile(tokenFile, []byte("short-lived-1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	signer, err := NewVaultTransitSigner(server.URL, tokenFile, "", "transit", "audit-checkpoint", "audit-checkpoint-hsm", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(context.Background(), "audit-checkpoint", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte("short-lived-2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := signer.Verify(context.Background(), "audit-checkpoint", []byte("payload"), signature); err != nil {
		t.Fatal(err)
	}
	if err := signer.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(observedTokens) < 6 || observedTokens[0] != "short-lived-1" {
		t.Fatalf("first request did not read first token: %v", observedTokens)
	}
	for _, token := range observedTokens[1:] {
		if token != "short-lived-2" {
			t.Fatalf("request reused a stale/static token: %v", observedTokens)
		}
	}
}

func TestVaultTransitSignerRejectsPlaintextAndWorldReadableToken(t *testing.T) {
	if _, err := NewVaultTransitSigner("http://vault.example", "/token", "", "transit", "audit-checkpoint", "audit-checkpoint-hsm", nil); err == nil {
		t.Fatal("plaintext Vault endpoint accepted")
	}
	tokenFile := filepath.Join(t.TempDir(), "agent-token")
	if err := os.WriteFile(tokenFile, []byte("token"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readVaultAgentToken(tokenFile); err == nil {
		t.Fatal("world-readable Vault token accepted")
	}
}
