package auditexport

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/example/payment-platform/internal/audit"
)

const (
	ManifestFormat = "payment-platform/audit-manifest/v1"
	RetentionYears = 10
)

// manifestV1 deliberately contains no maps, floats, interface values, or
// omitempty fields. encoding/json therefore emits one stable field order and
// representation across retries. Sequences are decimal strings so downstream
// JSON consumers cannot round an INT8 through IEEE-754.
type manifestV1 struct {
	Format                 string  `json:"format"`
	BookID                 string  `json:"book_id"`
	FirstSequence          string  `json:"first_sequence"`
	LastSequence           string  `json:"last_sequence"`
	LeafCount              string  `json:"leaf_count"`
	MerkleRootSHA256       string  `json:"merkle_root_sha256"`
	LastEntrySHA256        string  `json:"last_entry_sha256"`
	PreviousCheckpointRoot *string `json:"previous_checkpoint_root_sha256"`
	SigningKeyID           string  `json:"signing_key_id"`
	Signature              string  `json:"signature_base64"`
	CheckpointCreatedAt    string  `json:"checkpoint_created_at"`
	RetentionUntil         string  `json:"retention_until"`
}

type Artifact struct {
	BookID       string
	LastSequence int64
	Format       string
	ObjectKey    string
	Bytes        []byte
	SHA256       [32]byte
	RetainUntil  time.Time
}

func BuildManifest(checkpoint audit.Checkpoint) (Artifact, error) {
	if checkpoint.BookID == "" || checkpoint.FirstSequence <= 0 ||
		checkpoint.LastSequence < checkpoint.FirstSequence ||
		checkpoint.LeafCount != checkpoint.LastSequence-checkpoint.FirstSequence+1 ||
		checkpoint.SigningKeyID == "" || len(checkpoint.Signature) == 0 ||
		checkpoint.CreatedAt.IsZero() {
		return Artifact{}, errors.New("audit export: incomplete checkpoint")
	}
	created := checkpoint.CreatedAt.UTC()
	retention := created.AddDate(RetentionYears, 0, 0)
	var previous *string
	if checkpoint.PreviousCheckpointRoot != nil {
		encoded := hex.EncodeToString(checkpoint.PreviousCheckpointRoot[:])
		previous = &encoded
	}
	canonical := manifestV1{
		Format:                 ManifestFormat,
		BookID:                 checkpoint.BookID,
		FirstSequence:          strconv.FormatInt(checkpoint.FirstSequence, 10),
		LastSequence:           strconv.FormatInt(checkpoint.LastSequence, 10),
		LeafCount:              strconv.FormatInt(checkpoint.LeafCount, 10),
		MerkleRootSHA256:       hex.EncodeToString(checkpoint.MerkleRoot[:]),
		LastEntrySHA256:        hex.EncodeToString(checkpoint.LastEntryHash[:]),
		PreviousCheckpointRoot: previous,
		SigningKeyID:           checkpoint.SigningKeyID,
		Signature:              base64.StdEncoding.EncodeToString(checkpoint.Signature),
		CheckpointCreatedAt:    created.Format(time.RFC3339Nano),
		RetentionUntil:         retention.Format(time.RFC3339Nano),
	}
	body, err := json.Marshal(canonical)
	if err != nil {
		return Artifact{}, fmt.Errorf("audit export: encode manifest: %w", err)
	}
	body = append(body, '\n')
	digest := sha256.Sum256(body)
	bookNamespace := sha256.Sum256([]byte(checkpoint.BookID))
	key := fmt.Sprintf(
		"audit/v1/book-sha256=%s/sequence=%020d-%020d/sha256=%s.json",
		hex.EncodeToString(bookNamespace[:]), checkpoint.FirstSequence,
		checkpoint.LastSequence, hex.EncodeToString(digest[:]),
	)
	return Artifact{
		BookID: checkpoint.BookID, LastSequence: checkpoint.LastSequence,
		Format: ManifestFormat, ObjectKey: key, Bytes: body, SHA256: digest,
		RetainUntil: retention,
	}, nil
}
