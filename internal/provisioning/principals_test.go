package provisioning

import (
	"errors"
	"testing"
)

const walletPolicy = `{
  "spiffe://payments.test/provisioning-client/wallet-app": {
    "default": "wallet",
    "principals": {
      "wallet": "spiffe://payments.test/wallet/payments-service",
      "treasury": "spiffe://payments.test/treasury/payments-service"
    }
  }
}`

func mustAllowlist(t *testing.T, document string) *Allowlist {
	t.Helper()
	allowlist, err := ParseAllowlist([]byte(document))
	if err != nil {
		t.Fatalf("parse allowlist: %v", err)
	}
	return allowlist
}

func TestAllowlistResolvesOnlyPermittedSelectors(t *testing.T) {
	allowlist := mustAllowlist(t, walletPolicy)
	caller := "spiffe://payments.test/provisioning-client/wallet-app"

	for selector, want := range map[string]string{
		"":         "spiffe://payments.test/wallet/payments-service",
		"wallet":   "spiffe://payments.test/wallet/payments-service",
		"treasury": "spiffe://payments.test/treasury/payments-service",
	} {
		got, err := allowlist.Resolve(caller, selector)
		if err != nil {
			t.Fatalf("resolve %q: %v", selector, err)
		}
		if got != want {
			t.Fatalf("resolve %q = %q, want %q", selector, got, want)
		}
	}
}

// The whole point of the indirection: a caller must not be able to name a
// principal of its own choosing, even one that looks plausible.
func TestAllowlistRefusesPrincipalsTheCallerInvents(t *testing.T) {
	allowlist := mustAllowlist(t, walletPolicy)
	caller := "spiffe://payments.test/provisioning-client/wallet-app"

	for _, selector := range []string{
		"spiffe://payments.test/attacker/payments-service",
		"unknown",
		"WALLET",
		"wallet ",
	} {
		if _, err := allowlist.Resolve(caller, selector); !errors.Is(err, ErrPrincipalDenied) {
			t.Fatalf("selector %q resolved instead of being denied: err=%v", selector, err)
		}
	}
}

func TestAllowlistRefusesUnknownCallers(t *testing.T) {
	allowlist := mustAllowlist(t, walletPolicy)
	if _, err := allowlist.Resolve("spiffe://payments.test/provisioning-client/other", "wallet"); !errors.Is(err, ErrPrincipalDenied) {
		t.Fatalf("unknown caller resolved: err=%v", err)
	}
	if _, err := allowlist.Resolve("", ""); !errors.Is(err, ErrPrincipalDenied) {
		t.Fatalf("empty caller resolved: err=%v", err)
	}
}

// A single permitted principal is unambiguous, so omitting the selector is
// allowed; several are not, and must not silently pick one.
func TestAllowlistDefaultRequiresAnUnambiguousChoice(t *testing.T) {
	single := mustAllowlist(t, `{
  "spiffe://payments.test/provisioning-client/solo": {
    "principals": {"only": "spiffe://payments.test/wallet/payments-service"}
  }
}`)
	got, err := single.Resolve("spiffe://payments.test/provisioning-client/solo", "")
	if err != nil || got != "spiffe://payments.test/wallet/payments-service" {
		t.Fatalf("single-principal default = %q, err=%v", got, err)
	}

	ambiguous := mustAllowlist(t, `{
  "spiffe://payments.test/provisioning-client/multi": {
    "principals": {
      "a": "spiffe://payments.test/wallet/a",
      "b": "spiffe://payments.test/wallet/b"
    }
  }
}`)
	if _, err := ambiguous.Resolve("spiffe://payments.test/provisioning-client/multi", ""); !errors.Is(err, ErrPrincipalDenied) {
		t.Fatalf("ambiguous default silently resolved: err=%v", err)
	}
}

func TestAllowlistRejectsUnusableDocuments(t *testing.T) {
	for name, document := range map[string]string{
		"not json":           `{`,
		"empty":              `{}`,
		"no principals":      `{"spiffe://c": {"principals": {}}}`,
		"unknown default":    `{"spiffe://c": {"default": "missing", "principals": {"a": "spiffe://p"}}}`,
		"blank principal":    `{"spiffe://c": {"principals": {"a": ""}}}`,
		"untrimmed selector": `{"spiffe://c": {"principals": {" a": "spiffe://p"}}}`,
	} {
		if _, err := ParseAllowlist([]byte(document)); err == nil {
			t.Fatalf("%s: unusable allowlist was accepted", name)
		}
	}
}

func TestUnconfiguredAllowlistDeniesEverything(t *testing.T) {
	var allowlist *Allowlist
	if _, err := allowlist.Resolve("spiffe://c", "a"); err == nil {
		t.Fatal("nil allowlist resolved a principal")
	}
}
