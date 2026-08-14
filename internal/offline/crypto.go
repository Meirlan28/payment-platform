package offline

import (
	"context"
	"fmt"
)

func verifyAllowance(ctx context.Context, verifier Verifier, allowance Allowance) (VerifiedAllowance, error) {
	if verifier == nil || len(allowance.Signature) == 0 {
		return VerifiedAllowance{}, ErrInvalidSignature
	}
	payload, err := allowance.CanonicalPayload()
	if err != nil {
		return VerifiedAllowance{}, err
	}
	if err := verifier.Verify(ctx, allowance.KeyID, payload, allowance.Signature); err != nil {
		return VerifiedAllowance{}, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	return VerifiedAllowance{allowance: allowance, payloadHash: allowanceHash(payload)}, nil
}

func verifyPresentation(
	ctx context.Context,
	allowanceVerifier Verifier,
	presentationVerifier PresentationVerifier,
	presentation Presentation,
) (VerifiedPresentation, error) {
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
		ctx, binding, payload, presentation.Signature,
	); err != nil {
		return VerifiedPresentation{}, fmt.Errorf("%w: %w", ErrInvalidPresentation, err)
	}
	return VerifiedPresentation{
		presentation: presentation,
		allowance: allowance,
		payload: append([]byte(nil), payload...),
		payloadHash: sha256Sum(payload),
		presentationHash: presentationEnvelopeHash(payload, presentation.Signature),
		challengeHash: sha256Sum(presentation.MerchantChallenge[:]),
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
			KeyID: value.closure.KeyID,
		}
		if err := verifier.VerifyClosure(ctx, binding, value.payload, value.closure.Signature); err != nil {
			return verifiedClosureSet{}, fmt.Errorf("%w: %w", ErrInvalidClosure, err)
		}
	}
	return result, nil
}

func canonicalizeClosureSet(request FenceRequest) (verifiedClosureSet, error) {
	values := make(map[string]verifiedClosure, len(request.DomainClosures))
	for _, closure := range request.DomainClosures {
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
			closure: closure,
			payload: append([]byte(nil), payload...),
			payloadHash: sha256Sum(payload),
			evidenceHash: closureEnvelopeHash(payload, closure.Signature),
		}
	}
	result := verifiedClosureSet{byDomain: values}
	result.setHash = closureSetHash(values)
	return result, nil
}

func allowanceHash(payload []byte) [32]byte {
	// Kept in a tiny helper so all DB comparisons use the exact bytes verified
	// by the KMS adapter rather than re-marshalled transport data.
	return sha256Sum(payload)
}
