package audit

import (
	"crypto/sha256"
	"encoding/binary"
)

var merkleNodeDomain = []byte("payment-platform/merkle-node/v1\x00")

// MerkleRoot duplicates an odd final node at each level. The domain separator
// prevents an internal node from being confused with a raw ledger entry hash.
func MerkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		return sha256.Sum256([]byte("payment-platform/merkle-empty/v1\x00"))
	}
	level := append([][32]byte(nil), leaves...)
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			right := level[i]
			if i+1 < len(level) {
				right = level[i+1]
			}
			h := sha256.New()
			h.Write(merkleNodeDomain)
			h.Write(level[i][:])
			h.Write(right[:])
			var size [8]byte
			binary.BigEndian.PutUint64(size[:], uint64(i/2))
			h.Write(size[:])
			var parent [32]byte
			copy(parent[:], h.Sum(nil))
			next = append(next, parent)
		}
		level = next
	}
	return level[0]
}
