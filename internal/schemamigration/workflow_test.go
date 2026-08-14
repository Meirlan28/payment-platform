package schemamigration

import (
	"crypto/sha256"
	"testing"
)

func TestDigestEncodingIsUnambiguousAndDeterministic(t *testing.T) {
	first := digestRow{
		bookID: "ab", sequence: 7, transactionID: "c", referenceType: ReferenceType,
		referenceID: "target", schemaVersion: 2,
	}
	second := digestRow{
		bookID: "a", sequence: 7, transactionID: "bc", referenceType: ReferenceType,
		referenceID: "target", schemaVersion: 2,
	}

	hashRow := func(row digestRow) [32]byte {
		digest := sha256.New()
		_, _ = digest.Write([]byte(digestDomain))
		writeDigestRow(digest, row)
		var result [32]byte
		copy(result[:], digest.Sum(nil))
		return result
	}
	if hashRow(first) == hashRow(second) {
		t.Fatal("length-prefixed fields must not collide when boundaries move")
	}
	if hashRow(first) != hashRow(first) {
		t.Fatal("canonical projection digest is not deterministic")
	}
}

func TestPhaseOrdering(t *testing.T) {
	if !phaseAtLeast(PhaseContracted, PhaseVerified) {
		t.Fatal("contracted must be later than verified")
	}
	if phaseAtLeast(PhaseShadowing, PhaseCutover) {
		t.Fatal("shadowing must not satisfy cutover")
	}
}
