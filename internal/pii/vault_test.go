package pii

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

func TestTransitEncryptDecryptAndDestroy(t *testing.T) {
	var mu sync.Mutex
	var requests []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			t.Error("Vault token header missing")
		}
		mu.Lock()
		requests = append(requests, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/v1/transit/keys/pii-key", "/v1/transit/keys/pii-key/config":
			w.WriteHeader(http.StatusNoContent)
		case "/v1/transit/encrypt/pii-key":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"ciphertext": "vault:v1:cipher"}})
		case "/v1/transit/decrypt/pii-key":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{
				"plaintext": base64.StdEncoding.EncodeToString([]byte("secret")),
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewTransitClient(server.URL, "test-token", "", "transit", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := client.Encrypt(context.Background(), "pii-key", []byte("secret"), []byte("KZ\x00pty"))
	if err != nil || ciphertext != "vault:v1:cipher" {
		t.Fatalf("Encrypt() = %q, %v", ciphertext, err)
	}
	plaintext, err := client.Decrypt(context.Background(), "pii-key", ciphertext, []byte("KZ\x00pty"))
	if err != nil || string(plaintext) != "secret" {
		t.Fatalf("Decrypt() = %q, %v", plaintext, err)
	}
	if err := client.DestroyKey(context.Background(), "pii-key"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 5 {
		t.Fatalf("request sequence length = %d: %v", len(requests), requests)
	}
}

func TestTransitRejectsPlainHTTPAndUnsafeKeyName(t *testing.T) {
	if _, err := NewTransitClient("http://vault", "token", "", "", nil); err == nil {
		t.Fatal("plain HTTP Vault endpoint must be rejected")
	}
	client := &TransitClient{BaseURL: &url.URL{Scheme: "https", Host: "vault"}, HTTPClient: http.DefaultClient}
	if _, err := client.Encrypt(context.Background(), "../key", []byte("x"), nil); err == nil {
		t.Fatal("unsafe key name must be rejected")
	}
}
