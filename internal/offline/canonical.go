package offline

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
)

const (
	allowanceDomain            = "payment-platform/offline-allowance/v1\x00"
	effectDomain               = "payment-platform/offline-redemption-effect/v1\x00"
	proofDomain                = "payment-platform/offline-non-redemption-proof/v1\x00"
	presentationDomain         = "payment-platform/offline-presentation/v1\x00"
	presentationEnvelopeDomain = "payment-platform/offline-presentation-envelope/v1\x00"
	closureDomain              = "payment-platform/offline-acceptance-domain-closure/v1\x00"
	closureEvidenceDomain      = "payment-platform/offline-closure-evidence/v1\x00"
	closureSetDomain           = "payment-platform/offline-closure-set/v1\x00"
)

// CanonicalPayload is the sole representation accepted by signers and
// verifiers. Variable fields are length-prefixed, fixed-width integers are
// big-endian, and money remains a canonical base-10 DECIMAL(38,0) string.
func (a Allowance) CanonicalPayload() ([]byte, error) {
	if err := a.ValidatePayload(); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 256)
	out = append(out, allowanceDomain...)
	out = appendUint16(out, a.Version)
	// Keep the mandated financial fields in this explicit order. KeyID is
	// signed last to prevent key-substitution/algorithm-confusion attacks.
	for _, value := range []string{a.AccountID, a.AssetID, a.OriginRegion} {
		out = appendString(out, value)
	}
	out = append(out, a.DeviceIdentityHash[:]...)
	out = appendUint64(out, a.Counter)
	out = appendString(out, a.Amount.String())
	out = appendUint64(out, a.IssuerEpoch)
	out = appendString(out, a.AllowanceID)
	out = appendString(out, a.KeyID)
	return out, nil
}

func (a Allowance) PayloadHash() ([32]byte, error) {
	payload, err := a.CanonicalPayload()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(payload), nil
}

func (p Presentation) CanonicalPayload() ([]byte, error) {
	if err := p.ValidatePayload(); err != nil {
		return nil, err
	}
	allowanceHash, err := p.Allowance.PayloadHash()
	if err != nil || allowanceHash != p.AllowancePayloadHash ||
		p.SettlementEpoch != p.Allowance.IssuerEpoch ||
		p.UploadFence != p.Allowance.Counter {
		return nil, ErrInvalidPresentation
	}
	out := append([]byte(nil), presentationDomain...)
	out = appendUint16(out, p.Version)
	out = append(out, p.AllowancePayloadHash[:]...)
	out = appendString(out, p.MerchantAccountID)
	out = appendString(out, p.AcceptanceDomain)
	out = append(out, p.MerchantChallenge[:]...)
	out = appendUint64(out, p.SettlementEpoch)
	out = appendUint64(out, p.UploadFence)
	out = appendUint64(out, p.PresentationCounter)
	out = appendString(out, p.DeviceKeyID)
	return out, nil
}

func (p Presentation) PayloadHash() ([32]byte, error) {
	payload, err := p.CanonicalPayload()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(payload), nil
}

func presentationEnvelopeHash(payload, signature []byte) [32]byte {
	out := append([]byte(nil), presentationEnvelopeDomain...)
	out = appendBytes(out, payload)
	out = appendBytes(out, signature)
	return sha256.Sum256(out)
}

func (c DomainClosure) CanonicalPayload() ([]byte, error) {
	if err := c.ValidatePayload(); err != nil {
		return nil, err
	}
	out := append([]byte(nil), closureDomain...)
	out = appendUint16(out, c.Version)
	out = appendString(out, c.AcceptanceDomain)
	for _, value := range []string{c.AccountID, c.AssetID, c.OriginRegion} {
		out = appendString(out, value)
	}
	out = append(out, c.DeviceIdentityHash[:]...)
	out = appendUint64(out, c.ClosedSettlementEpoch)
	out = appendUint64(out, c.ClosedUploadFence)
	out = appendString(out, c.KeyID)
	return out, nil
}

func closureEnvelopeHash(payload, signature []byte) [32]byte {
	out := append([]byte(nil), closureEvidenceDomain...)
	out = appendBytes(out, payload)
	out = appendBytes(out, signature)
	return sha256.Sum256(out)
}

func closureSetHash(closures map[string]verifiedClosure) [32]byte {
	domains := make([]string, 0, len(closures))
	for domain := range closures {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	out := append([]byte(nil), closureSetDomain...)
	out = appendUint32(out, uint32(len(domains)))
	for _, domain := range domains {
		out = appendString(out, domain)
		value := closures[domain]
		out = append(out, value.evidenceHash[:]...)
	}
	return sha256.Sum256(out)
}

func (e RedemptionEffect) Hash() ([32]byte, error) {
	if err := e.validate(); err != nil {
		return [32]byte{}, err
	}
	out := append([]byte(nil), effectDomain...)
	out = appendString(out, e.EffectID)
	out = appendString(out, e.LedgerTransactionID)
	out = append(out, e.PostingRequestHash[:]...)
	return sha256.Sum256(out), nil
}

func hashProof(request FenceRequest, fenceVersion uint64, closureHash [32]byte) [32]byte {
	out := append([]byte(nil), proofDomain...)
	out = appendString(out, request.AllowanceID)
	out = append(out, request.ExpectedPayloadHash[:]...)
	out = appendUint64(out, request.ExpectedIssuerEpoch)
	out = appendUint64(out, request.ExpectedDeviceCounter)
	out = appendString(out, string(request.Kind))
	out = appendUint64(out, fenceVersion)
	out = append(out, request.PolicyEvidenceHash[:]...)
	out = append(out, closureHash[:]...)
	return sha256.Sum256(out)
}

func appendBytes(out, value []byte) []byte {
	out = appendUint32(out, uint32(len(value)))
	return append(out, value...)
}

func appendString(out []byte, value string) []byte {
	out = appendUint32(out, uint32(len(value)))
	return append(out, value...)
}

func appendUint16(out []byte, value uint16) []byte {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	return append(out, encoded[:]...)
}

func appendUint32(out []byte, value uint32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return append(out, encoded[:]...)
}

func appendUint64(out []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(out, encoded[:]...)
}
