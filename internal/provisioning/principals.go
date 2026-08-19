package provisioning

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Allowlist decides which payment principal a provisioning caller may have
// spending capability granted to.
//
// This indirection is the difference between a provisioning API and a
// privilege-escalation API. If the request carried a principal string
// directly, anyone holding a stolen provisioning credential could open an
// account and grant AUTHORIZE_PAYER_AVAILABLE on it to a principal they
// control. Instead the request carries only a selector, and the mapping from
// (authenticated caller, selector) to a real principal is deployment
// configuration that the caller cannot influence.
type Allowlist struct {
	callers map[string]callerPolicy
}

type callerPolicy struct {
	// DefaultSelector is used when a request omits the selector.
	DefaultSelector string `json:"default"`
	// Principals maps a selector to the payment principal it names.
	Principals map[string]string `json:"principals"`
}

// ParseAllowlist reads the JSON policy document:
//
//	{
//	  "spiffe://payments.example/provisioning-client/wallet-app": {
//	    "default": "wallet",
//	    "principals": {
//	      "wallet": "spiffe://payments.example/wallet/payments-service"
//	    }
//	  }
//	}
//
// An empty document is rejected: a provisioning service that can grant nothing
// is a misconfiguration, and failing at startup is safer than discovering it
// on the first onboarding request.
func ParseAllowlist(raw []byte) (*Allowlist, error) {
	var document map[string]callerPolicy
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("%w: provisioning allowlist is not valid JSON: %v", ErrInvalidRequest, err)
	}
	if len(document) == 0 {
		return nil, fmt.Errorf("%w: provisioning allowlist is empty", ErrInvalidRequest)
	}
	allowlist := &Allowlist{callers: make(map[string]callerPolicy, len(document))}
	for caller, policy := range document {
		if !boundedID(caller) {
			return nil, fmt.Errorf("%w: allowlist caller identity is invalid", ErrInvalidRequest)
		}
		if len(policy.Principals) == 0 {
			return nil, fmt.Errorf("%w: caller %q permits no payment principal", ErrInvalidRequest, caller)
		}
		for selector, principal := range policy.Principals {
			if !boundedID(selector) || !boundedID(principal) {
				return nil, fmt.Errorf("%w: caller %q has an invalid selector or principal", ErrInvalidRequest, caller)
			}
		}
		if policy.DefaultSelector != "" {
			if _, ok := policy.Principals[policy.DefaultSelector]; !ok {
				return nil, fmt.Errorf("%w: caller %q default selector %q is not permitted",
					ErrInvalidRequest, caller, policy.DefaultSelector)
			}
		} else if len(policy.Principals) == 1 {
			// A single permitted principal is unambiguous, so an explicit
			// default is not required to omit the selector.
			for selector := range policy.Principals {
				policy.DefaultSelector = selector
			}
		}
		allowlist.callers[caller] = policy
	}
	return allowlist, nil
}

// LoadAllowlistFile reads the policy from disk so it can be mounted as a
// secret or config map rather than baked into an image.
func LoadAllowlistFile(path string) (*Allowlist, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: provisioning allowlist path is required", ErrInvalidRequest)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read provisioning allowlist: %w", err)
	}
	return ParseAllowlist(raw)
}

// Resolve maps an authenticated caller and a requested selector to the payment
// principal that may receive capability. An unknown caller, an unknown
// selector, or an omitted selector with no unambiguous default are all
// refused; the function never falls back to the caller's own identity or to
// any value taken from the request.
func (a *Allowlist) Resolve(caller, selector string) (string, error) {
	if a == nil || len(a.callers) == 0 {
		return "", fmt.Errorf("%w: provisioning allowlist is not configured", ErrInvalidRequest)
	}
	policy, known := a.callers[caller]
	if !known {
		return "", fmt.Errorf("%w: caller %q is not permitted to provision accounts", ErrPrincipalDenied, caller)
	}
	if selector == "" {
		if policy.DefaultSelector == "" {
			return "", fmt.Errorf("%w: caller %q must name one of %s",
				ErrPrincipalDenied, caller, strings.Join(policy.selectors(), ", "))
		}
		selector = policy.DefaultSelector
	}
	principal, permitted := policy.Principals[selector]
	if !permitted {
		return "", fmt.Errorf("%w: caller %q may not grant capability to selector %q",
			ErrPrincipalDenied, caller, selector)
	}
	return principal, nil
}

func (p callerPolicy) selectors() []string {
	names := make([]string, 0, len(p.Principals))
	for selector := range p.Principals {
		names = append(names, selector)
	}
	sort.Strings(names)
	return names
}
