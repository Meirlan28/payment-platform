package auditexport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

var ErrWORMConflict = errors.New("audit export: immutable object conflict")

type SinkDescriptor struct {
	ID                string
	EndpointAuthority string
	Bucket            string
	IdentityDomain    string
}

type ObjectEvidence struct {
	VersionID        string
	ETag             string
	ProviderIdentity string
	RetentionUntil   time.Time
}

type Sink interface {
	Descriptor() SinkDescriptor
	Probe(context.Context) error
	Ensure(context.Context, Artifact) (ObjectEvidence, error)
	Verify(context.Context, Artifact) (ObjectEvidence, error)
}

type ConflictError struct {
	SinkID         string
	BookID         string
	LastSequence   int64
	ObjectKey      string
	ExpectedSHA256 [32]byte
	ObservedSHA256 *[32]byte
	Reason         string
}

func (e *ConflictError) Error() string {
	if e == nil {
		return ErrWORMConflict.Error()
	}
	return fmt.Sprintf("%v: sink=%s book=%s last_sequence=%d reason=%s",
		ErrWORMConflict, e.SinkID, e.BookID, e.LastSequence, e.Reason)
}

func (e *ConflictError) Unwrap() error { return ErrWORMConflict }

func (e *ConflictError) IncidentID() [32]byte {
	if e == nil {
		return sha256.Sum256([]byte("payment-platform/worm-conflict/nil"))
	}
	var canonical bytes.Buffer
	canonical.WriteString("payment-platform/worm-conflict/v1\x00")
	for _, value := range []string{e.SinkID, e.BookID, e.ObjectKey, e.Reason} {
		_ = binary.Write(&canonical, binary.BigEndian, uint32(len(value)))
		canonical.WriteString(value)
	}
	_ = binary.Write(&canonical, binary.BigEndian, e.LastSequence)
	canonical.Write(e.ExpectedSHA256[:])
	if e.ObservedSHA256 == nil {
		canonical.WriteByte(0)
	} else {
		canonical.WriteByte(1)
		canonical.Write(e.ObservedSHA256[:])
	}
	return sha256.Sum256(canonical.Bytes())
}

func validateTwoIndependentSinks(sinks []Sink) error {
	if len(sinks) != 2 || sinks[0] == nil || sinks[1] == nil {
		return errors.New("audit export: exactly two WORM sinks are required")
	}
	left, right := sinks[0].Descriptor(), sinks[1].Descriptor()
	for _, descriptor := range []SinkDescriptor{left, right} {
		if descriptor.ID == "" || descriptor.EndpointAuthority == "" ||
			descriptor.Bucket == "" || descriptor.IdentityDomain == "" {
			return errors.New("audit export: incomplete WORM sink identity")
		}
	}
	if left.ID == right.ID || left.EndpointAuthority == right.EndpointAuthority ||
		left.Bucket == right.Bucket || left.IdentityDomain == right.IdentityDomain {
		return errors.New("audit export: WORM sinks must use distinct IDs, endpoints, buckets, and identity domains")
	}
	return nil
}
