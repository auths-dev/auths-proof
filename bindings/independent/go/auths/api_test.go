package auths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func proofFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join(
		"..", "..", "..", "..",
		"core", "fixtures", "v1", "valid", name,
	)
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestVerifyReturnsNativeAuthorizedResult(t *testing.T) {
	t.Parallel()
	manifestBytes, err := os.ReadFile(filepath.Join(
		"..", "..", "..", "..", "core", "fixtures", "v1", "manifest.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	var corpus manifest
	if err := json.Unmarshal(manifestBytes, &corpus); err != nil {
		t.Fatal(err)
	}
	engine := &Engine{adapters: corpus.AdapterContext}
	result := engine.Verify(
		proofFixture(t, "raw-key-chain.proof.cbor"),
		proofFixture(t, "raw-key-chain.action.cbor"),
		proofFixture(t, "raw-key-chain.context.cbor"),
	)
	if result.Decision != Authorized || result.Code != "authorized" {
		t.Fatalf("unexpected result: %s/%s", result.Decision, result.Code)
	}
	if result.Action == nil {
		t.Fatal("authorized result omitted its sealed action")
	}
	if got := result.Action.CanonicalBytes(); string(got) != string(proofFixture(t, "raw-key-chain.action.cbor")) {
		t.Fatal("verified action bytes changed")
	}
	if result.Explanation().Retryable {
		t.Fatal("authorized result must not be retryable")
	}
}

func TestSharedCorpusRunsInNativeGoTest(t *testing.T) {
	t.Parallel()
	path := filepath.Join(
		"..", "..", "..", "..",
		"core", "fixtures", "v1", "manifest.json",
	)
	digest, err := AuditCorpus(path, true)
	if err != nil {
		t.Fatal(err)
	}
	// Behavior change: the corpus gained `action-budget-absent-budget-free-profile`,
	// the authorizing mirror of `action-budget-absent`. The pin covers 104 fixtures
	// and is the same digest `cargo xtask cross-language` requires of Rust, Go, and
	// the independent TypeScript verifier.
	const expected = "104:979e94789848596358786439265dc3b0d857a26ef2c1e13ae8b439ff23e24f67"
	if digest != expected {
		t.Fatalf("semantic corpus digest mismatch: got %s", digest)
	}
}
