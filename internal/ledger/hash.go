package ledger

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const ledgerHashDomain = "payment-platform/ledger-entry/v1\x00"

// CanonicalJSON removes insignificant whitespace and sorts object keys through
// encoding/json. JSON numbers are retained as json.Number; binary float
// conversion is never used.
func CanonicalJSON(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 {
		return []byte("{}"), nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("multiple JSON values")
		}
		return nil, err
	}
	return json.Marshal(value)
}

// HashEntry is the one canonical audit hash implementation used by both the
// writer and verifier. Variable fields are uint32-length-prefixed; integers are
// big-endian. Lines are hashed in their persisted 1-based line_no order.
func HashEntry(prevHash [32]byte, sequenceNo int64, request PostRequest) ([32]byte, error) {
	var zero [32]byte
	if sequenceNo <= 0 {
		return zero, fmt.Errorf("%w: sequence must be positive", ErrInvalidPosting)
	}
	if err := request.Validate(); err != nil {
		return zero, err
	}
	metadata, err := CanonicalJSON(request.Metadata)
	if err != nil {
		return zero, err
	}

	var canonical bytes.Buffer
	canonical.WriteString(ledgerHashDomain)
	canonical.Write(prevHash[:])
	writeInt64(&canonical, sequenceNo)
	for _, value := range []string{
		request.TransactionID,
		request.BookID,
		request.OperationID,
		request.EffectID,
		request.Kind,
		request.PostingRuleVersion,
	} {
		if err := writeBytes(&canonical, []byte(value)); err != nil {
			return zero, err
		}
	}
	writeInt64(&canonical, request.SchemaVersion)
	if request.ReferenceTransactionID == nil {
		canonical.WriteByte(0)
	} else {
		canonical.WriteByte(1)
		if err := writeBytes(&canonical, []byte(*request.ReferenceTransactionID)); err != nil {
			return zero, err
		}
	}
	canonical.Write(request.RequestHash[:])
	if err := writeBytes(&canonical, metadata); err != nil {
		return zero, err
	}
	writeUint32(&canonical, uint32(len(request.Lines)))
	for index, line := range request.Lines {
		writeInt64(&canonical, int64(index+1))
		for _, value := range []string{line.AccountID, line.AssetID, string(line.Side), line.Memo} {
			if err := writeBytes(&canonical, []byte(value)); err != nil {
				return zero, err
			}
		}
		if err := writeBytes(&canonical, []byte(line.AmountAtoms.String())); err != nil {
			return zero, err
		}
	}
	return sha256.Sum256(canonical.Bytes()), nil
}

// CanonicalEntryHash is the audit-verifier API. It accepts the previous hash
// exactly as stored in CockroachDB and recomputes the hash from every immutable
// financial header field and the ordered lines. Status and wall-clock columns
// are intentionally excluded: they are lifecycle/audit metadata, not inputs to
// the financial fact committed by entry_hash.
func CanonicalEntryHash(prevHash []byte, transaction Transaction) ([]byte, error) {
	if len(prevHash) != sha256.Size {
		return nil, errors.New("ledger: previous hash must contain 32 bytes")
	}
	var previous [32]byte
	copy(previous[:], prevHash)
	calculated, err := HashEntry(previous, transaction.SequenceNo, transaction.PostRequest)
	if err != nil {
		return nil, err
	}
	result := make([]byte, len(calculated))
	copy(result, calculated[:])
	return result, nil
}

func GenesisHash(bookID string) [32]byte {
	return sha256.Sum256([]byte("payment-platform/ledger-genesis/v1\x00" + bookID))
}

func writeBytes(dst *bytes.Buffer, value []byte) error {
	if uint64(len(value)) > uint64(^uint32(0)) {
		return errors.New("ledger: canonical field exceeds uint32")
	}
	writeUint32(dst, uint32(len(value)))
	dst.Write(value)
	return nil
}

func writeUint32(dst *bytes.Buffer, value uint32) {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	dst.Write(raw[:])
}

func writeInt64(dst *bytes.Buffer, value int64) {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], uint64(value))
	dst.Write(raw[:])
}
