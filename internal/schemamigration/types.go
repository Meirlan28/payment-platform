// Package schemamigration implements the operational state machine for an
// online ledger schema change.  Financial history remains immutable; only a
// rebuildable projection and migration-control metadata are written.
package schemamigration

import (
	"errors"
	"time"
)

const (
	ReferenceMigration = "ledger-reference-v2"
	ReferenceType      = "LEDGER_TRANSACTION"
)

type Phase string

const (
	PhaseExpanded   Phase = "EXPANDED"
	PhaseShadowing  Phase = "SHADOWING"
	PhaseVerified   Phase = "VERIFIED"
	PhaseCutover    Phase = "CUTOVER"
	PhaseContracted Phase = "CONTRACTED"
)

var (
	ErrStaleState         = errors.New("schema migration: stale state version")
	ErrWrongPhase         = errors.New("schema migration: operation is invalid in current phase")
	ErrWrongGeneration    = errors.New("schema migration: generation is not active")
	ErrProjectionMismatch = errors.New("schema migration: source and shadow projection differ")
	ErrWatermarkCorrupt   = errors.New("schema migration: ledger watermark no longer proves the captured head")
	ErrContractBlocked    = errors.New("schema migration: required consumers have not acknowledged cutover")
)

type Status struct {
	MigrationName    string    `json:"migration_name"`
	ActiveGeneration int64     `json:"active_generation"`
	ReadGeneration   int64     `json:"read_generation"`
	Phase            Phase     `json:"phase"`
	StateVersion     int64     `json:"state_version"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type Verification struct {
	Generation      int64    `json:"generation"`
	SourceRows      int64    `json:"source_rows"`
	ProjectedRows   int64    `json:"projected_rows"`
	SourceDigest    [32]byte `json:"source_digest"`
	ProjectedDigest [32]byte `json:"projected_digest"`
}

type BackfillReport struct {
	Generation     int64  `json:"generation"`
	BookID         string `json:"book_id,omitempty"`
	RowsScanned    int64  `json:"rows_scanned"`
	ReferencesSeen int64  `json:"references_seen"`
	Batches        int64  `json:"batches"`
	Complete       bool   `json:"complete"`
}

// Reference is returned by the generation-aware reader. Found=false is a
// valid financial operation with no reference, not a missing transaction.
type Reference struct {
	TransactionID       string `json:"transaction_id"`
	ReferenceType       string `json:"reference_type,omitempty"`
	ReferenceID         string `json:"reference_id,omitempty"`
	SourceSchemaVersion int64  `json:"source_schema_version"`
	ReadGeneration      int64  `json:"read_generation"`
	Found               bool   `json:"found"`
}

func phaseAtLeast(current, target Phase) bool {
	rank := map[Phase]int{
		PhaseExpanded: 0, PhaseShadowing: 1, PhaseVerified: 2,
		PhaseCutover: 3, PhaseContracted: 4,
	}
	return rank[current] >= rank[target]
}
