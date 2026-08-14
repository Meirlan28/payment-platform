//go:build integration

package pii

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

type piiTestIDs struct{ next atomic.Int64 }

func (g *piiTestIDs) Next(context.Context) (string, error) {
	return fmt.Sprintf("pii-integration-%d", g.next.Add(1)), nil
}

type memoryKeyManager struct {
	mu        sync.Mutex
	destroyed map[string]bool
	keys      map[string][]byte
}

func (m *memoryKeyManager) Encrypt(_ context.Context, key string, plaintext, aad []byte) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.destroyed == nil {
		m.destroyed = make(map[string]bool)
	}
	if m.keys == nil {
		m.keys = make(map[string][]byte)
	}
	material := make([]byte, 32)
	if _, err := rand.Read(material); err != nil {
		return "", err
	}
	m.keys[key] = material
	block, err := aes.NewCipher(material)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, plaintext, aad)
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

func (m *memoryKeyManager) Decrypt(_ context.Context, key, ciphertext string, aad []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.destroyed[key] {
		return nil, ErrIdentityDeleted
	}
	material := m.keys[key]
	if len(material) == 0 {
		return nil, ErrIdentityDeleted
	}
	raw, err := base64.RawStdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(material)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < aead.NonceSize() {
		return nil, errors.New("ciphertext truncated")
	}
	return aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], aad)
}

func (m *memoryKeyManager) DestroyKey(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.destroyed[key] = true
	delete(m.keys, key)
	return nil
}

func TestCryptoShreddingDeletesPIIButKeepsDeletionEvidence(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	keys := &memoryKeyManager{destroyed: make(map[string]bool), keys: make(map[string][]byte)}
	service := &Service{
		RegionalDB: map[string]*pgxpool.Pool{"KZ": pool}, IDs: &piiTestIDs{},
		Regional: map[string]KeyManager{"KZ": keys},
	}
	identityID, err := service.Create(ctx, "KZ", map[string]string{
		"name": "Sensitive Person", "email": "secret@example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	var ciphertext string
	if err := pool.QueryRow(ctx, `SELECT ciphertext FROM pii.identity_mappings WHERE identity_id=$1`, identityID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ciphertext, "Sensitive Person") || strings.Contains(ciphertext, "secret@example.test") {
		t.Fatal("PII leaked into the mapping database as plaintext")
	}
	identity, err := service.Get(ctx, "KZ", identityID)
	if err != nil || identity.Attributes["email"] != "secret@example.test" {
		t.Fatalf("Get() = %#v, %v", identity, err)
	}
	requestID := "deletion-" + identityID
	if err := service.RequestDeletion(ctx, "KZ", identityID, requestID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Get(ctx, "KZ", identityID); !errors.Is(err, ErrIdentityDeleted) {
		t.Fatalf("deleted identity remained readable: %v", err)
	}
	if err := service.RequestDeletion(ctx, "KZ", identityID, requestID); err != nil {
		t.Fatalf("deletion retry must be idempotent: %v", err)
	}
	var receipt string
	if err := pool.QueryRow(ctx, `SELECT result FROM pii.deletion_receipts WHERE request_id=$1`, requestID).Scan(&receipt); err != nil {
		t.Fatal(err)
	}
	if receipt != "KEY_DESTROYED_AND_MAPPING_DELETED" {
		t.Fatalf("unexpected deletion receipt %q", receipt)
	}
}
