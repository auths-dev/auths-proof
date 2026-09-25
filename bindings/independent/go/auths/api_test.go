package auths

import (
	"bytes"
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

func corpusEngine(t *testing.T) *Engine {
	t.Helper()
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
	return &Engine{adapters: corpus.AdapterContext}
}

func invalidFixture(t *testing.T, name string) []byte {
	t.Helper()
	value, err := os.ReadFile(filepath.Join(
		"..", "..", "..", "..", "core", "fixtures", "v1", "invalid", name,
	))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestVerifyDeniesOverLimitActionInputAtDecode(t *testing.T) {
	t.Parallel()
	result := corpusEngine(t).Verify(
		invalidFixture(t, "action-input-bytes-over-limit.proof.cbor"),
		invalidFixture(t, "action-input-bytes-over-limit.action.cbor"),
		invalidFixture(t, "action-input-bytes-over-limit.context.cbor"),
	)
	if result.Decision != Denied || result.Code != "resource-limit-exceeded" {
		t.Fatalf("unexpected result: %s/%s", result.Decision, result.Code)
	}
	if len(result.PlanID) != 0 || result.Action != nil {
		t.Fatal("an action rejected at decode must leave no plan and no verified action")
	}
}

// The same byte-level mutations of the raw-key-chain canonical action are
// checked against the native decoder in auths-verifier's portable
// conformance test; both must return these codes.
func TestCanonicalActionDecodeFailuresUseNativeCodes(t *testing.T) {
	t.Parallel()
	engine := corpusEngine(t)
	proof := proofFixture(t, "raw-key-chain.proof.cbor")
	context := proofFixture(t, "raw-key-chain.context.cbor")
	action := proofFixture(t, "raw-key-chain.action.cbor")
	for _, mutation := range canonicalActionMutations(action) {
		result := engine.Verify(proof, mutation.bytes, context)
		if result.Decision != Denied || result.Code != mutation.code {
			t.Fatalf("%s: got %s/%s, want denied/%s", mutation.name, result.Decision, result.Code, mutation.code)
		}
		if len(result.PlanID) != 0 {
			t.Fatalf("%s: a decode failure must leave no plan", mutation.name)
		}
	}
}

type actionMutation struct {
	name  string
	bytes []byte
	code  string
}

func replaceOnce(source, from, to []byte) []byte {
	index := bytes.Index(source, from)
	if index < 0 || bytes.Index(source[index+1:], from) >= 0 {
		panic("mutation site is not unique")
	}
	output := append([]byte(nil), source[:index]...)
	output = append(output, to...)
	return append(output, source[index+len(from):]...)
}

func canonicalActionMutations(action []byte) []actionMutation {
	digest := func(fill byte) []byte { return bytes.Repeat([]byte{fill}, 32) }
	attachments := func(first, second []byte) []byte {
		output := []byte{0x05, 0x82}
		for _, value := range [][]byte{first, second} {
			output = append(output, 0xa2, 0x00, 0x58, 0x20)
			output = append(output, value...)
			output = append(output, 0x01, 0x41, 0x01)
		}
		return output
	}
	bodyAt := bytes.Index(action, []byte{0x02, 0x58, 0x18})
	permissionAt := bytes.Index(action, []byte{0x03, 0xa2})
	emptyBody := append(append([]byte(nil), action[:bodyAt]...), 0x02, 0x40)
	emptyBody = append(emptyBody, action[permissionAt:]...)
	return []actionMutation{
		{"truncated", action[:len(action)-1], "malformed-proof"},
		{"trailing byte", append(append([]byte(nil), action...), 0x00), "malformed-proof"},
		{"map size", append([]byte{0xa5}, action[1:]...), "malformed-proof"},
		{"key out of order", replaceOnce(action, []byte{0x05, 0x80}, []byte{0x06, 0x80}), "non-canonical-proof"},
		{"non-shortest key", append([]byte{0xa6, 0x18, 0x00}, action[2:]...), "non-canonical-proof"},
		{"zero profile version", replaceOnce(action, []byte("auths.mcp\x01\x01"), []byte("auths.mcp\x01\x00")), "malformed-proof"},
		{"whitespace in media type", replaceOnce(action, []byte("auths.mcp-call"), []byte("auths mcp-call")), "malformed-proof"},
		{"body as text", replaceOnce(action, []byte{0x02, 0x58, 0x18}, []byte{0x02, 0x78, 0x18}), "malformed-proof"},
		{"empty body", emptyBody, "resource-limit-exceeded"},
		{"indefinite attachments", replaceOnce(action, []byte{0x05, 0x80}, []byte{0x05, 0x9f, 0xff}), "malformed-proof"},
		{"attachments out of order", replaceOnce(action, []byte{0x05, 0x80}, attachments(digest(0xff), digest(0x00))), "non-canonical-proof"},
		{"duplicate attachments", replaceOnce(action, []byte{0x05, 0x80}, attachments(digest(0xaa), digest(0xaa))), "malformed-proof"},
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
	// The pin covers 233 fixtures after the check-precedence vectors and is
	// the same digest `cargo xtask cross-language` requires of Rust, Go, and
	// the independent TypeScript verifier.
	const expected = "233:73eacb65d1d7a66d75884228edf8ba8976cb2fcf2de7f4f6cca3f7c8154774b1"
	if digest != expected {
		t.Fatalf("semantic corpus digest mismatch: got %s", digest)
	}
}
