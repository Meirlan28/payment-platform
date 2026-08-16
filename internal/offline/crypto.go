package offline

import (
	"context"
	"fmt"
)

func verifyAllowance(ctx context.Context, verifier Verifier, allowance Allowance) (VerifiedAllowance, error) {
	// Own every caller-provided byte before crossing the verifier boundary, and
	// never let an adapter retain an alias to the value we return. Transport
	// objects may be pooled and verifier implementations may retain their input
	// buffers for telemetry, so both sides of the boundary receive copies.
	allowance = cloneAllowance(allowance)
	if verifier == nil || len(allowance.Signature) == 0 {
		return VerifiedAllowance{}, ErrInvalidSignature
	}
	payload, err := allowance.CanonicalPayload()
	if err != nil {
		return VerifiedAllowance{}, err
	}
	if err := verifier.Verify(ctx, allowance.KeyID,
		append([]byte(nil), payload...), append([]byte(nil), allowance.Signature...)); err != nil {
		return VerifiedAllowance{}, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	allowance = cloneAllowance(allowance)
	payload, err = allowance.CanonicalPayload()
	if err != nil {
		return VerifiedAllowance{}, err
	}
	return VerifiedAllowance{
		allowance:   allowance,
		payload:     append([]byte(nil), payload...),
		payloadHash: allowanceHash(payload),
	}, nil
}

func verifyPresentation(
	ctx context.Context,
	allowanceVerifier Verifier,
	presentationVerifier PresentationVerifier,
	presentation Presentation,
) (VerifiedPresentation, error) {
	presentation = clonePresentation(presentation)
	if presentationVerifier == nil || len(presentation.Signature) == 0 {
		return VerifiedPresentation{}, ErrInvalidPresentation
	}
	allowance, err := verifyAllowance(ctx, allowanceVerifier, presentation.Allowance)
	if err != nil {
		return VerifiedPresentation{}, err
	}
	payload, err := presentation.CanonicalPayload()
	if err != nil {
		return VerifiedPresentation{}, err
	}
	if allowance.payloadHash != presentation.AllowancePayloadHash {
		return VerifiedPresentation{}, ErrInvalidPresentation
	}
	binding := PresentationKeyBinding{
		DeviceIdentityHash: presentation.Allowance.DeviceIdentityHash,
		DeviceKeyID:        presentation.DeviceKeyID,
	}
	if err := presentationVerifier.VerifyPresentation(
		ctx, binding, append([]byte(nil), payload...),
		append([]byte(nil), presentation.Signature...),
	); err != nil {
		return VerifiedPresentation{}, fmt.Errorf("%w: %w", ErrInvalidPresentation, err)
	}
	presentation = clonePresentation(presentation)
	payload, err = presentation.CanonicalPayload()
	if err != nil || presentation.AllowancePayloadHash != allowance.payloadHash ||
		!sameAllowanceEnvelope(presentation.Allowance, allowance.allowance) {
		return VerifiedPresentation{}, ErrInvalidPresentation
	}
	return VerifiedPresentation{
		presentation:     presentation,
		allowance:        allowance,
		payload:          append([]byte(nil), payload...),
		payloadHash:      sha256Sum(payload),
		presentationHash: presentationEnvelopeHash(payload, presentation.Signature),
		challengeHash:    sha256Sum(presentation.MerchantChallenge[:]),
	}, nil
}

func verifyClosureSet(
	ctx context.Context,
	verifier ClosureVerifier,
	request FenceRequest,
) (verifiedClosureSet, error) {
	if verifier == nil {
		return verifiedClosureSet{}, ErrInvalidClosure
	}
	result, err := canonicalizeClosureSet(request)
	if err != nil {
		return verifiedClosureSet{}, err
	}
	for _, value := range result.byDomain {
		binding := ClosureKeyBinding{
			AcceptanceDomain: value.closure.AcceptanceDomain,
			KeyID:            value.closure.KeyID,
		}
		if err := verifier.VerifyClosure(ctx, binding,
			append([]byte(nil), value.payload...),
			append([]byte(nil), value.closure.Signature...)); err != nil {
			return verifiedClosureSet{}, fmt.Errorf("%w: %w", ErrInvalidClosure, err)
		}
	}
	result = cloneVerifiedClosureSet(result)
	if err := validateVerifiedClosureSet(result); err != nil {
		return verifiedClosureSet{}, err
	}
	return result, nil
}

func canonicalizeClosureSet(request FenceRequest) (verifiedClosureSet, error) {
	values := make(map[string]verifiedClosure, len(request.DomainClosures))
	for _, input := range request.DomainClosures {
		closure := cloneDomainClosure(input)
		payload, err := closure.CanonicalPayload()
		if err != nil || len(closure.Signature) == 0 {
			return verifiedClosureSet{}, ErrInvalidClosure
		}
		if _, duplicate := values[closure.AcceptanceDomain]; duplicate {
			return verifiedClosureSet{}, ErrIncompleteClosure
		}
		if closure.ClosedSettlementEpoch < request.ExpectedIssuerEpoch ||
			(closure.ClosedSettlementEpoch == request.ExpectedIssuerEpoch &&
				closure.ClosedUploadFence < request.ExpectedDeviceCounter) {
			return verifiedClosureSet{}, ErrIncompleteClosure
		}
		values[closure.AcceptanceDomain] = verifiedClosure{
			closure:      closure,
			payload:      append([]byte(nil), payload...),
			payloadHash:  sha256Sum(payload),
			evidenceHash: closureEnvelopeHash(payload, closure.Signature),
		}
	}
	result := verifiedClosureSet{byDomain: values}
	result.setHash = closureSetHash(values)
	return result, nil
}

func cloneAllowance(value Allowance) Allowance {
	value.Signature = append([]byte(nil), value.Signature...)
	return value
}

func clonePresentation(value Presentation) Presentation {
	value.Allowance = cloneAllowance(value.Allowance)
	value.Signature = append([]byte(nil), value.Signature...)
	return value
}

func cloneDomainClosure(value DomainClosure) DomainClosure {
	value.Signature = append([]byte(nil), value.Signature...)
	return value
}

func cloneVerifiedClosureSet(value verifiedClosureSet) verifiedClosureSet {
	result := verifiedClosureSet{
		byDomain: make(map[string]verifiedClosure, len(value.byDomain)),
		setHash:  value.setHash,
	}
	for domain, closure := range value.byDomain {
		closure.closure = cloneDomainClosure(closure.closure)
		closure.payload = append([]byte(nil), closure.payload...)
		result.byDomain[domain] = closure
	}
	return result
}

func allowanceHash(payload []byte) [32]byte {
	// Kept in a tiny helper so all DB comparisons use the exact bytes verified
	// by the KMS adapter rather than re-marshalled transport data.
	return sha256Sum(payload)
}
