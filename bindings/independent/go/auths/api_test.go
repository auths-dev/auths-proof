package auths

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
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
	if result.Decision != Authorized || result.Code != "authorized" || result.Stage != "complete" {
		t.Fatalf("unexpected result: %s/%s at %s", result.Decision, result.Code, result.Stage)
	}
	if len(result.PlanID) == 0 {
		t.Fatal("authorized result omitted its plan")
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
	if result.Decision != Denied || result.Code != "resource-limit-exceeded" || result.Stage != "decode" {
		t.Fatalf("unexpected result: %s/%s at %s", result.Decision, result.Code, result.Stage)
	}
	if len(result.PlanID) != 0 || result.Action != nil {
		t.Fatal("an action rejected at decode must leave no plan and no verified action")
	}
}

// Every corpus vector whose canonical action is carried as raw bytes has its
// fault in that encoding, so Verify must reject it at decode with the
// manifest's decision and code and report no plan.
func TestRawCanonicalActionVectorsFailAtDecode(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "..", "..", "core", "fixtures", "v1")
	manifestBytes, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus manifest
	if err := json.Unmarshal(manifestBytes, &corpus); err != nil {
		t.Fatal(err)
	}
	engine := &Engine{adapters: corpus.AdapterContext}
	read := func(value string) []byte {
		t.Helper()
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(value)))
		if err != nil {
			t.Fatal(err)
		}
		return content
	}
	count := 0
	for _, vector := range corpus.Fixtures {
		if vector.CanonicalAction.Encoding != "raw" {
			continue
		}
		count++
		result := engine.Verify(
			read(vector.Proof.Path),
			read(vector.CanonicalAction.Path),
			read(vector.Context.Path),
		)
		if string(result.Decision) != vector.ExpectedDecision ||
			result.Code != vector.ExpectedCode || result.Stage != "decode" {
			t.Errorf(
				"%s: got %s/%s at %s, want %s/%s at decode",
				vector.Name, result.Decision, result.Code, result.Stage,
				vector.ExpectedDecision, vector.ExpectedCode,
			)
		}
		if len(result.PlanID) != 0 || result.Action != nil {
			t.Errorf("%s: a decode failure must leave no plan and no verified action", vector.Name)
		}
	}
	if count == 0 {
		t.Fatal("the corpus carries no raw canonical-action vector")
	}
}

func TestSharedCorpusRunsInNativeGoTest(t *testing.T) {
	t.Parallel()
	path := filepath.Join(
		"..", "..", "..", "..",
		"core", "fixtures", "v1", "manifest.json",
	)
	digest, err := AuditSemantic(path, "")
	if err != nil {
		t.Fatal(err)
	}
	// The pin covers 287 fixtures after the status-scope, raw action-decode,
	// and reason-order vectors, with the stage in every vector's fields, and is
	// the same digest `cargo xtask cross-language` requires of Rust, Go, and
	// the independent TypeScript verifier.
	const expected = "287:be4f133a9a8956e1e933cc954749d1b9ef27a2f2465f93d72a1bf412134f1d9c"
	if digest != expected {
		t.Fatalf("semantic corpus digest mismatch: got %s", digest)
	}
}

// corpusVector returns the proof, canonical action, and context bytes of the
// named corpus vector.
func corpusVector(t *testing.T, name string) (proof, action, context []byte) {
	t.Helper()
	root := filepath.Join("..", "..", "..", "..", "core", "fixtures", "v1")
	manifestBytes, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus manifest
	if err := json.Unmarshal(manifestBytes, &corpus); err != nil {
		t.Fatal(err)
	}
	read := func(value string) []byte {
		t.Helper()
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(value)))
		if err != nil {
			t.Fatal(err)
		}
		return content
	}
	for _, vector := range corpus.Fixtures {
		if vector.Name == name {
			return read(vector.Proof.Path), read(vector.CanonicalAction.Path), read(vector.Context.Path)
		}
	}
	t.Fatalf("the corpus has no vector %s", name)
	return nil, nil, nil
}

// Every map key of the canonical action, in the action map and in the maps
// nested in its fields, is read before its value: an unsigned integer below
// 256 other than the next expected key is non-canonical-proof, and any other
// key item is malformed-proof. The corpus pins only the action map's own key.
func TestCanonicalActionKeysNestedInFields(t *testing.T) {
	t.Parallel()
	engine := corpusEngine(t)
	proof := proofFixture(t, "raw-key-chain.proof.cbor")
	context := proofFixture(t, "raw-key-chain.context.cbor")
	action := proofFixture(t, "raw-key-chain.action.cbor")
	splice := func(from, to []byte) []byte {
		t.Helper()
		if bytes.Count(action, from) != 1 {
			t.Fatalf("splice site %x is not unique", from)
		}
		return bytes.Replace(action, from, to, 1)
	}
	profileKey := []byte("auths.mcp\x01\x01")
	cases := []struct {
		name  string
		bytes []byte
		code  string
	}{
		{"a profile key out of order", splice(profileKey, []byte("auths.mcp\x02\x01")), "non-canonical-proof"},
		{"a permission key out of order", splice([]byte{0x03, 0xa2, 0x00}, []byte{0x03, 0xa2, 0x01}), "non-canonical-proof"},
		{"a budget key out of order", splice([]byte{0x04, 0xa2, 0x00}, []byte{0x04, 0xa2, 0x01}), "non-canonical-proof"},
		{"a profile key in a longer form", splice(profileKey, []byte("auths.mcp\x18\x01\x01")), "non-canonical-proof"},
		{"a profile key of 256", splice(profileKey, []byte("auths.mcp\x19\x01\x00\x01")), "malformed-proof"},
		{"a text profile key", splice(profileKey, []byte("auths.mcp\x61\x61\x01")), "malformed-proof"},
		{"a negative profile key", splice(profileKey, []byte("auths.mcp\x20\x01")), "malformed-proof"},
		{"an action key of 256", append([]byte{0xa6, 0x19, 0x01, 0x00}, action[2:]...), "malformed-proof"},
		{"a tagged action key", append([]byte{0xa6, 0xc0, 0x00}, action[2:]...), "malformed-proof"},
	}
	for _, testCase := range cases {
		result := engine.Verify(proof, testCase.bytes, context)
		if result.Decision != Denied || result.Code != testCase.code || result.Stage != stageDecode ||
			len(result.PlanID) != 0 {
			t.Errorf("%s: got %s/%s at %s, want denied/%s at decode",
				testCase.name, result.Decision, result.Code, result.Stage, testCase.code)
		}
	}
}

// encodeTree re-encodes a decoded CBOR tree, reusing the bytes of every node
// that still has them. A test clears raw on each container it edits.
func encodeTree(value *cborValue) []byte {
	if value.raw != nil {
		return value.raw
	}
	switch value.major {
	case 4:
		output := encodeCBORHead(4, uint64(len(value.array)))
		for _, child := range value.array {
			output = append(output, encodeTree(child)...)
		}
		return output
	case 5:
		output := encodeCBORHead(5, uint64(len(value.pairs)))
		for _, pair := range value.pairs {
			output = append(output, encodeTree(pair.key)...)
			output = append(output, encodeTree(pair.value)...)
		}
		return output
	default:
		panic("only an edited container lacks its encoding")
	}
}

// withStatusTrust replaces the trust-rule arrays of a context's principal and
// grant snapshots with the given encoded arrays.
func withStatusTrust(t *testing.T, context []byte, principalTrust, grantTrust []byte) []byte {
	t.Helper()
	root, err := decodeValue(context)
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range root.pairs {
		if pair.key.uint != 9 && pair.key.uint != 10 {
			continue
		}
		trust := principalTrust
		if pair.key.uint == 10 {
			trust = grantTrust
		}
		for index := range pair.value.pairs {
			if pair.value.pairs[index].key.uint == 5 {
				pair.value.pairs[index].value = &cborValue{raw: trust}
			}
		}
		pair.value.raw = nil
	}
	root.raw = nil
	return encodeTree(root)
}

var (
	ownScope = []byte{0xa1, 0x00, 0x00}
	anyScope = []byte{0xa1, 0x00, 0x02}
)

func anchorsScope(ids ...string) []byte {
	output := append([]byte{0xa2, 0x00, 0x01, 0x01}, encodeCBORHead(4, uint64(len(ids)))...)
	for _, id := range ids {
		output = append(output, encodeCBORText(id)...)
	}
	return output
}

func trustRule(method, issuer string, floor uint64, scope []byte) []byte {
	output := append(encodeCBORHead(5, 4), 0x00)
	output = append(append(output, encodeCBORText(method)...), 0x01)
	output = append(append(output, encodeCBORText(issuer)...), 0x02)
	output = append(append(output, encodeCBORHead(0, floor)...), 0x03)
	return append(output, scope...)
}

func trustRules(rules ...[]byte) []byte {
	output := encodeCBORHead(4, uint64(len(rules)))
	for _, rule := range rules {
		output = append(output, rule...)
	}
	return output
}

// Status scope shapes decode only as {0: 0}, {0: 1, 1: [ids]}, or {0: 2},
// with an anchors list in strictly ascending UTF-8 byte order.
func TestDecodeStatusScopeShapes(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", maxBoundedIDBytes)
	sequence := func(count int) []string {
		ids := make([]string, count)
		for index := range ids {
			ids[index] = fmt.Sprintf("anchor-%04d", index)
		}
		return ids
	}
	listed := func(ids ...string) *statusScope {
		return &statusScope{kind: statusScopeAnchors, anchors: ids}
	}
	cases := []struct {
		name  string
		bytes []byte
		want  *statusScope // nil: the scope does not decode
	}{
		{"own", ownScope, &statusScope{kind: statusScopeOwn}},
		{"any", anyScope, &statusScope{kind: statusScopeAny}},
		{"anchors", anchorsScope("a", "b"), listed("a", "b")},
		{"byte order, not length-first order", anchorsScope("aa", "b"), listed("aa", "b")},
		{"an ID at the byte limit", anchorsScope(long), listed(long)},
		{"the maximum list", anchorsScope(sequence(maxStatusScopeAnchors)...), listed(sequence(maxStatusScopeAnchors)...)},
		{"length-first order", anchorsScope("b", "aa"), nil},
		{"unsorted", anchorsScope("b", "a"), nil},
		{"a repeated ID", anchorsScope("a", "a"), nil},
		{"an empty list", anchorsScope(), nil},
		{"an empty ID", anchorsScope(""), nil},
		{"an ID over the byte limit", anchorsScope(long + "a"), nil},
		{"a list over the maximum", anchorsScope(sequence(maxStatusScopeAnchors + 1)...), nil},
		{"an ID that is not text", []byte{0xa2, 0x00, 0x01, 0x01, 0x81, 0x41, 0x61}, nil},
		{"anchors without a list", []byte{0xa1, 0x00, 0x01}, nil},
		{"own with another key", []byte{0xa2, 0x00, 0x00, 0x01, 0x80}, nil},
		{"any with another key", []byte{0xa2, 0x00, 0x02, 0x01, 0x80}, nil},
		{"an unknown tag", []byte{0xa1, 0x00, 0x03}, nil},
		{"a text tag", []byte{0xa1, 0x00, 0x60}, nil},
		{"not a map", []byte{0x00}, nil},
	}
	for _, testCase := range cases {
		value, err := decodeValue(testCase.bytes)
		if err != nil {
			t.Fatalf("%s: the test input is not deterministic CBOR: %v", testCase.name, err)
		}
		scope, err := decodeStatusScope(value)
		switch {
		case testCase.want == nil && err == nil:
			t.Errorf("%s: decoded, want a decode error", testCase.name)
		case testCase.want != nil && err != nil:
			t.Errorf("%s: %v", testCase.name, err)
		case testCase.want != nil && !scope.equal(*testCase.want):
			t.Errorf("%s: got %+v, want %+v", testCase.name, scope, *testCase.want)
		}
	}
}

func scopeBytes(scope statusScope) []byte {
	switch scope.kind {
	case statusScopeOwn:
		return ownScope
	case statusScopeAny:
		return anyScope
	default:
		return anchorsScope(scope.anchors...)
	}
}

func encodeTrustRules(rules []statusTrustRule) []byte {
	encoded := make([][]byte, 0, len(rules))
	for _, rule := range rules {
		encoded = append(encoded, trustRule(rule.method, rule.issuer, rule.minimumSequence, scopeBytes(rule.scope)))
	}
	return trustRules(encoded...)
}

// withAnchors returns context bytes whose trust-anchor array is order applied
// to the context's anchors.
func withAnchors(t *testing.T, context []byte, order func([]*cborValue) []*cborValue) []byte {
	t.Helper()
	root, err := decodeValue(context)
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range root.pairs {
		if pair.key.uint == 3 {
			pair.value.array = order(append([]*cborValue(nil), pair.value.array...))
			pair.value.raw = nil
		}
	}
	root.raw = nil
	return encodeTree(root)
}

func requireDecodeFailure(t *testing.T, name string, result Result) {
	t.Helper()
	if result.Decision != Denied || result.Code != "malformed-proof" || result.Stage != stageDecode ||
		len(result.PlanID) != 0 {
		t.Errorf("%s: got %s/%s at %s, want denied/malformed-proof at decode",
			name, result.Decision, result.Code, result.Stage)
	}
}

// Splices of status-scope-baseline, whose two anchors each have one own-scope
// rule with floor 1 in each snapshot. A context whose status scope can apply
// to no anchor, or that gives one issuer two scopes in one snapshot, is
// malformed-proof at decode.
func TestStatusScopeContextValidity(t *testing.T) {
	t.Parallel()
	engine := corpusEngine(t)
	proof, action, base := corpusVector(t, "status-scope-baseline")
	decoded := mustDecodeContext(t, base)
	principalRules, grantRules := decoded.principalSnapshot.trust, decoded.grantSnapshot.trust
	principal, grant := encodeTrustRules(principalRules), encodeTrustRules(grantRules)
	if len(principalRules) != 2 || len(grantRules) != 2 ||
		!bytes.Equal(withStatusTrust(t, base, principal, grant), base) {
		t.Fatal("the baseline's rules are not two own-scope rules per snapshot")
	}
	const (
		otherMethod = "other-status-v1"
		service     = "key:sha256:status-service"
	)
	change := func(rules []statusTrustRule, edit func([]statusTrustRule) []statusTrustRule) []byte {
		return encodeTrustRules(edit(append([]statusTrustRule(nil), rules...)))
	}
	ownAnchors := func(rules []statusTrustRule) []statusTrustRule {
		for index := range rules {
			for _, anchor := range decoded.anchors {
				if anchor.principal == rules[index].issuer {
					rules[index].scope = statusScope{kind: statusScopeAnchors, anchors: []string{anchor.id}}
				}
			}
		}
		return rules
	}
	anyAnchor := func(rules []statusTrustRule) []statusTrustRule {
		for index := range rules {
			rules[index].scope = statusScope{kind: statusScopeAny}
		}
		return rules
	}
	secondMethod := func(scope statusScope) func([]statusTrustRule) []statusTrustRule {
		return func(rules []statusTrustRule) []statusTrustRule {
			return append(rules, statusTrustRule{
				method: otherMethod, issuer: rules[1].issuer, minimumSequence: 1, scope: scope,
			})
		}
	}
	unknownAnchor := func(rules []statusTrustRule) []statusTrustRule {
		rules[0].scope = statusScope{kind: statusScopeAnchors, anchors: []string{"no-such-anchor"}}
		return rules
	}
	unknownIssuer := func(rules []statusTrustRule) []statusTrustRule {
		rules[1].issuer = service
		return rules
	}
	valid := []struct {
		name             string
		principal, grant []byte
	}{
		{"the baseline", principal, grant},
		{"anchors listing each issuer's anchor", change(principalRules, ownAnchors), change(grantRules, ownAnchors)},
		{"any for every issuer", change(principalRules, anyAnchor), change(grantRules, anyAnchor)},
		{"one issuer, one scope, two methods", change(principalRules, secondMethod(principalRules[1].scope)), grant},
		{"one issuer with a different scope in each snapshot", principal, change(grantRules, anyAnchor)},
	}
	for _, testCase := range valid {
		result := engine.Verify(proof, action, withStatusTrust(t, base, testCase.principal, testCase.grant))
		if result.Decision != Authorized || result.Stage != stageComplete {
			t.Errorf("%s: got %s/%s at %s, want authorized", testCase.name, result.Decision, result.Code, result.Stage)
		}
	}
	first, second := principalRules[0], principalRules[1]
	threeEntryRule := append(encodeCBORHead(5, 3), 0x00)
	threeEntryRule = append(append(threeEntryRule, encodeCBORText(first.method)...), 0x01)
	threeEntryRule = append(append(threeEntryRule, encodeCBORText(first.issuer)...), 0x02, 0x01)
	indefiniteList := []byte{0xa2, 0x00, 0x01, 0x01, 0x9f}
	indefiniteList = append(append(indefiniteList, encodeCBORText(decoded.anchors[0].id)...), 0xff)
	secondRule := trustRule(second.method, second.issuer, second.minimumSequence, scopeBytes(second.scope))
	invalid := []struct {
		name             string
		principal, grant []byte
	}{
		{"a three-entry rule", trustRules(threeEntryRule, secondRule), grant},
		{"an indefinite anchors list", trustRules(trustRule(first.method, first.issuer, 1, indefiniteList), secondRule), grant},
		{"anchors listing an unknown anchor", change(principalRules, unknownAnchor), grant},
		{"own for an issuer that is no anchor principal", change(principalRules, unknownIssuer), grant},
		{"one issuer with two scopes", change(principalRules, secondMethod(statusScope{kind: statusScopeAny})), grant},
		{"anchors listing an unknown anchor in the grant snapshot", principal, change(grantRules, unknownAnchor)},
		{"own for a non-anchor issuer in the grant snapshot", principal, change(grantRules, unknownIssuer)},
		{"one issuer with two scopes in the grant snapshot", principal,
			change(grantRules, secondMethod(statusScope{kind: statusScopeAny}))},
	}
	for _, testCase := range invalid {
		requireDecodeFailure(t, testCase.name,
			engine.Verify(proof, action, withStatusTrust(t, base, testCase.principal, testCase.grant)))
	}
}

// The trust anchors ascend strictly in UTF-8 byte order of their IDs, so an
// anchors scope names each anchor once: an anchor out of order or repeated is
// malformed-proof at decode.
func TestTrustAnchorsAscendByID(t *testing.T) {
	t.Parallel()
	engine := corpusEngine(t)
	proof, action, base := corpusVector(t, "status-scope-baseline")
	unchanged := withAnchors(t, base, func(anchors []*cborValue) []*cborValue { return anchors })
	if len(mustDecodeContext(t, base).anchors) != 2 || !bytes.Equal(unchanged, base) {
		t.Fatal("the baseline does not have two re-encodable anchors")
	}
	if result := engine.Verify(proof, action, unchanged); result.Decision != Authorized {
		t.Fatalf("the baseline is %s/%s", result.Decision, result.Code)
	}
	cases := []struct {
		name  string
		order func([]*cborValue) []*cborValue
	}{
		{"out of order", func(anchors []*cborValue) []*cborValue {
			return []*cborValue{anchors[1], anchors[0]}
		}},
		{"a repeated first anchor", func(anchors []*cborValue) []*cborValue {
			return []*cborValue{anchors[0], anchors[0], anchors[1]}
		}},
		{"a repeated last anchor", func(anchors []*cborValue) []*cborValue {
			return []*cborValue{anchors[0], anchors[1], anchors[1]}
		}},
	}
	for _, testCase := range cases {
		requireDecodeFailure(t, testCase.name, engine.Verify(proof, action, withAnchors(t, base, testCase.order)))
	}
}

func mustDecodeContext(t *testing.T, context []byte) *verifierContext {
	t.Helper()
	decoded, err := decodeContext(context)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

// statusFixture is a two-organization status configuration: anchors V and F,
// a status service that is no anchor, and an issuer no rule names.
type statusFixture struct {
	anchorV, anchorF *trustAnchor
	context          *verifierContext
	controls         map[string]verifiedControl
	next             byte
}

const (
	testPrincipalMethod = "auths-principal-status-v1"
	testGrantMethod     = "auths-grant-status-v1"
	testOtherMethod     = "other-status-v1"
	testService         = "status-service"
	testUnknownIssuer   = "unknown-issuer"
)

func newStatusFixture() *statusFixture {
	anchorV := &trustAnchor{id: "anchor-v", principal: "root-v"}
	anchorF := &trustAnchor{id: "anchor-f", principal: "root-f"}
	rules := func(method string) []statusTrustRule {
		return []statusTrustRule{
			{method: method, issuer: "root-v", minimumSequence: 1, scope: statusScope{kind: statusScopeOwn}},
			{method: method, issuer: "root-f", minimumSequence: 1, scope: statusScope{kind: statusScopeOwn}},
		}
	}
	context := &verifierContext{
		anchors:           []*trustAnchor{anchorV, anchorF},
		principalStatuses: []string{testPrincipalMethod, testOtherMethod},
		grantStatuses:     []string{testGrantMethod},
		extensions:        []string{"exact-marker-v1"},
		evaluationTime:    50,
		principalSnapshot: statusSnapshot[principalStatus]{observedAt: 40, validUntil: 60, trust: rules(testPrincipalMethod)},
		grantSnapshot:     statusSnapshot[grantStatus]{observedAt: 40, validUntil: 60, trust: rules(testGrantMethod)},
	}
	return &statusFixture{
		anchorV: anchorV, anchorF: anchorF, context: context,
		controls: make(map[string]verifiedControl),
	}
}

func (fixture *statusFixture) id() []byte {
	fixture.next++
	return bytes.Repeat([]byte{fixture.next}, 32)
}

// principal adds a principal-status statement with verified control.
func (fixture *statusFixture) principal(subject, issuer, method string, state, sequence uint64) *principalStatus {
	statement := &principalStatus{
		method: method, principal: subject, state: state, sequence: sequence,
		observedAt: 40, validUntil: 60, issuer: issuer, id: fixture.id(),
	}
	fixture.context.principalSnapshot.statements = append(fixture.context.principalSnapshot.statements, statement)
	fixture.controls[statementReference{kind: 2, id: statement.id}.key()] = verifiedControl{}
	return statement
}

// grant adds a grant-status statement with verified control.
func (fixture *statusFixture) grant(grantID []byte, issuer string, state, sequence uint64) *grantStatus {
	statement := &grantStatus{
		method: testGrantMethod, grantID: grantID, state: state, sequence: sequence,
		observedAt: 40, validUntil: 60, issuer: issuer, id: fixture.id(),
	}
	fixture.context.grantSnapshot.statements = append(fixture.context.grantSnapshot.statements, statement)
	fixture.controls[statementReference{kind: 3, id: statement.id}.key()] = verifiedControl{}
	return statement
}

func (fixture *statusFixture) checkPrincipal(subject string, listing statusListing, anchor *trustAnchor) error {
	policy := statusPolicy{kind: 1, method: testPrincipalMethod, maxAge: 100}
	return checkPrincipalStatus(policy, subject, listing, anchor, fixture.context, fixture.controls)
}

func (fixture *statusFixture) checkGrant(grantID []byte, anchor *trustAnchor) error {
	policy := statusPolicy{kind: 1, method: testGrantMethod, maxAge: 100}
	return checkGrantStatus(policy, grantID, anchor, fixture.context, fixture.controls)
}

// A statement whose issuer's scope does not cover the branch's anchor takes
// no part in any status step; one whose issuer no rule names still does.
func TestOutOfScopeStatusStatementsAreIgnored(t *testing.T) {
	t.Parallel()
	grantID := bytes.Repeat([]byte{0xee}, 32)
	cases := []struct {
		name  string
		build func(*statusFixture) error
		want  error
	}{
		{"own issuer revokes its actor", func(f *statusFixture) error {
			f.principal("actor-v", "root-v", testPrincipalMethod, 1, 1)
			return f.checkPrincipal("actor-v", statusRevocationList, f.anchorV)
		}, denied("principal-revoked")},
		{"foreign revocation of the actor", func(f *statusFixture) error {
			f.principal("actor-v", "root-f", testPrincipalMethod, 1, 1)
			return f.checkPrincipal("actor-v", statusRevocationList, f.anchorV)
		}, nil},
		{"foreign reinstatement of the actor", func(f *statusFixture) error {
			f.principal("actor-v", "root-v", testPrincipalMethod, 1, 1)
			f.principal("actor-v", "root-f", testPrincipalMethod, 0, 2)
			return f.checkPrincipal("actor-v", statusRevocationList, f.anchorV)
		}, denied("principal-revoked")},
		{"foreign statement under a method without a rule", func(f *statusFixture) error {
			f.principal("actor-v", "root-f", testOtherMethod, 1, 1)
			return f.checkPrincipal("actor-v", statusRevocationList, f.anchorV)
		}, nil},
		{"foreign statement with an unknown extension", func(f *statusFixture) error {
			statement := f.principal("actor-v", "root-f", testPrincipalMethod, 1, 1)
			statement.extensions = []criticalExtension{{id: "unknown-extension-v1", bytes: []byte{1}}}
			return f.checkPrincipal("actor-v", statusRevocationList, f.anchorV)
		}, nil},
		{"foreign statement without control", func(f *statusFixture) error {
			statement := f.principal("actor-v", "root-f", testPrincipalMethod, 1, 1)
			delete(f.controls, statementReference{kind: 2, id: statement.id}.key())
			return f.checkPrincipal("actor-v", statusRevocationList, f.anchorV)
		}, nil},
		{"anchor principal with only a foreign statement", func(f *statusFixture) error {
			f.principal("root-v", "root-f", testPrincipalMethod, 0, 1)
			return f.checkPrincipal("root-v", statusRequired, f.anchorV)
		}, indeterminate("missing-principal-status")},
		{"partner revokes its own actor", func(f *statusFixture) error {
			f.principal("actor-f", "root-f", testPrincipalMethod, 1, 1)
			return f.checkPrincipal("actor-f", statusRevocationList, f.anchorF)
		}, denied("principal-revoked")},
		{"an issuer no rule names stays untrusted", func(f *statusFixture) error {
			f.principal("actor-v", testUnknownIssuer, testPrincipalMethod, 1, 1)
			return f.checkPrincipal("actor-v", statusRevocationList, f.anchorV)
		}, denied("status-issuer-untrusted")},
		{"a listed-anchors issuer inside its scope", func(f *statusFixture) error {
			f.context.principalSnapshot.trust = append(f.context.principalSnapshot.trust, statusTrustRule{
				method: testPrincipalMethod, issuer: testService, minimumSequence: 1,
				scope: statusScope{kind: statusScopeAnchors, anchors: []string{"anchor-f"}},
			})
			f.principal("actor-f", testService, testPrincipalMethod, 1, 1)
			return f.checkPrincipal("actor-f", statusRevocationList, f.anchorF)
		}, denied("principal-revoked")},
		{"a listed-anchors issuer outside its scope", func(f *statusFixture) error {
			f.context.principalSnapshot.trust = append(f.context.principalSnapshot.trust, statusTrustRule{
				method: testPrincipalMethod, issuer: testService, minimumSequence: 1,
				scope: statusScope{kind: statusScopeAnchors, anchors: []string{"anchor-f"}},
			})
			f.principal("actor-v", testService, testPrincipalMethod, 1, 1)
			return f.checkPrincipal("actor-v", statusRevocationList, f.anchorV)
		}, nil},
		{"an any-scope issuer revokes a partner actor", func(f *statusFixture) error {
			f.context.principalSnapshot.trust[0].scope = statusScope{kind: statusScopeAny}
			f.principal("actor-f", "root-v", testPrincipalMethod, 1, 1)
			return f.checkPrincipal("actor-f", statusRevocationList, f.anchorF)
		}, denied("principal-revoked")},
		{"own issuer revokes its grant", func(f *statusFixture) error {
			f.grant(grantID, "root-v", 0, 1)
			f.grant(grantID, "root-v", 1, 2)
			return f.checkGrant(grantID, f.anchorV)
		}, denied("grant-revoked")},
		{"foreign revocation of the grant", func(f *statusFixture) error {
			f.grant(grantID, "root-v", 0, 1)
			f.grant(grantID, "root-f", 1, 2)
			return f.checkGrant(grantID, f.anchorV)
		}, nil},
		{"foreign reinstatement of the grant", func(f *statusFixture) error {
			f.grant(grantID, "root-v", 1, 2)
			f.grant(grantID, "root-f", 0, 3)
			return f.checkGrant(grantID, f.anchorV)
		}, denied("grant-revoked")},
		{"a grant with only a foreign statement", func(f *statusFixture) error {
			f.grant(grantID, "root-f", 0, 1)
			return f.checkGrant(grantID, f.anchorV)
		}, indeterminate("missing-grant-status")},
	}
	for _, testCase := range cases {
		if got := testCase.build(newStatusFixture()); got != testCase.want {
			t.Errorf("%s: got %v, want %v", testCase.name, got, testCase.want)
		}
	}
}

// For random snapshots and scopes, the status result under each anchor equals
// the result on the same snapshot with that anchor's out-of-scope statements
// removed.
func TestOutOfScopeStatementsDoNotInterfere(t *testing.T) {
	t.Parallel()
	random := rand.New(rand.NewPCG(5, 64))
	pick := func(values ...string) string { return values[random.IntN(len(values))] }
	grantIDs := [][]byte{bytes.Repeat([]byte{0xa1}, 32), bytes.Repeat([]byte{0xa2}, 32)}
	// outside is the specification's definition, written apart from the
	// verifier's: a rule names the issuer and its scope does not cover the
	// anchor.
	outside := func(trust []statusTrustRule, issuer string, anchor *trustAnchor) bool {
		for _, rule := range trust {
			if rule.issuer != issuer {
				continue
			}
			switch rule.scope.kind {
			case statusScopeOwn:
				return issuer != anchor.principal
			case statusScopeAnchors:
				return !containsText(rule.scope.anchors, anchor.id)
			default:
				return false
			}
		}
		return false
	}
	randomScope := func(issuer string) statusScope {
		choices := []statusScope{
			{kind: statusScopeAny},
			{kind: statusScopeAnchors, anchors: []string{"anchor-f"}},
			{kind: statusScopeAnchors, anchors: []string{"anchor-v"}},
			{kind: statusScopeAnchors, anchors: []string{"anchor-f", "anchor-v"}},
		}
		if issuer == "root-v" || issuer == "root-f" {
			choices = append(choices, statusScope{kind: statusScopeOwn})
		}
		return choices[random.IntN(len(choices))]
	}
	for round := 0; round < 400; round++ {
		fixture := newStatusFixture()
		var principalTrust, grantTrust []statusTrustRule
		for _, issuer := range []string{"root-v", "root-f", testService} {
			scope := randomScope(issuer)
			for _, method := range []string{testPrincipalMethod, testOtherMethod} {
				if random.IntN(4) > 0 {
					principalTrust = append(principalTrust, statusTrustRule{
						method: method, issuer: issuer, minimumSequence: uint64(random.IntN(2)), scope: scope,
					})
				}
			}
			if random.IntN(4) > 0 {
				grantTrust = append(grantTrust, statusTrustRule{
					method: testGrantMethod, issuer: issuer, minimumSequence: uint64(random.IntN(2)), scope: scope,
				})
			}
		}
		fixture.context.principalSnapshot.trust = principalTrust
		fixture.context.grantSnapshot.trust = grantTrust
		issuers := []string{"root-v", "root-f", testService, testUnknownIssuer}
		for count := random.IntN(7); count > 0; count-- {
			statement := fixture.principal(
				pick("root-v", "root-f", "actor-v", "actor-f"), pick(issuers...),
				pick(testPrincipalMethod, testOtherMethod), uint64(random.IntN(3)), uint64(random.IntN(4)),
			)
			statement.validUntil = uint64(45 + random.IntN(20))
			if random.IntN(8) == 0 {
				statement.extensions = []criticalExtension{{id: pick("exact-marker-v1", "unknown-v1"), bytes: []byte{1}}}
			}
			if random.IntN(8) == 0 {
				fixture.controls[statementReference{kind: 2, id: statement.id}.key()] =
					verifiedControl{err: denied("invalid-signature")}
			}
		}
		for count := random.IntN(5); count > 0; count-- {
			statement := fixture.grant(
				grantIDs[random.IntN(len(grantIDs))], pick(issuers...), uint64(random.IntN(3)), uint64(random.IntN(4)),
			)
			if random.IntN(8) == 0 {
				delete(fixture.controls, statementReference{kind: 3, id: statement.id}.key())
			}
		}
		full := fixture.context
		for _, anchor := range []*trustAnchor{fixture.anchorV, fixture.anchorF} {
			reduced := *full
			reduced.principalSnapshot.statements = nil
			for _, statement := range full.principalSnapshot.statements {
				if !outside(full.principalSnapshot.trust, statement.issuer, anchor) {
					reduced.principalSnapshot.statements = append(reduced.principalSnapshot.statements, statement)
				}
			}
			reduced.grantSnapshot.statements = nil
			for _, statement := range full.grantSnapshot.statements {
				if !outside(full.grantSnapshot.trust, statement.issuer, anchor) {
					reduced.grantSnapshot.statements = append(reduced.grantSnapshot.statements, statement)
				}
			}
			for _, subject := range []string{"root-v", "root-f", "actor-v", "actor-f"} {
				for _, listing := range []statusListing{statusRequired, statusRevocationList} {
					fixture.context = full
					got := fixture.checkPrincipal(subject, listing, anchor)
					fixture.context = &reduced
					want := fixture.checkPrincipal(subject, listing, anchor)
					if got != want {
						t.Fatalf("round %d, %s under %s: got %v, without out-of-scope statements %v",
							round, subject, anchor.id, got, want)
					}
				}
			}
			for _, grantID := range grantIDs {
				fixture.context = full
				got := fixture.checkGrant(grantID, anchor)
				fixture.context = &reduced
				want := fixture.checkGrant(grantID, anchor)
				if got != want {
					t.Fatalf("round %d, grant %x under %s: got %v, without out-of-scope statements %v",
						round, grantID[:1], anchor.id, got, want)
				}
			}
			fixture.context = full
		}
	}
}

// Carried status is checked for rollback, keyed on subject, method, and
// issuer, across every carried statement before any is checked for holding.
func TestCarriedStatusRollbackBeforeHolding(t *testing.T) {
	t.Parallel()
	principal := func(subject, issuer, method string, sequence uint64, tag byte) *principalStatus {
		return &principalStatus{
			statement: &cborValue{raw: []byte{tag}}, principal: subject, issuer: issuer,
			method: method, sequence: sequence, signature: signatureEnvelope{signature: []byte{tag}},
		}
	}
	grantA := bytes.Repeat([]byte{0x0a}, 32)
	grantB := bytes.Repeat([]byte{0x0b}, 32)
	grant := func(grantID []byte, issuer string, sequence uint64, tag byte) *grantStatus {
		return &grantStatus{
			statement: &cborValue{raw: []byte{tag}}, grantID: grantID, issuer: issuer,
			method: testGrantMethod, sequence: sequence, signature: signatureEnvelope{signature: []byte{tag}},
		}
	}
	held := principal("actor-v", "root-v", testPrincipalMethod, 1, 1)
	heldGrant := grant(grantA, "root-v", 1, 20)
	cases := []struct {
		name           string
		carried        []*principalStatus
		carriedGrants  []*grantStatus
		snapshot       []*principalStatus
		snapshotGrants []*grantStatus
		want           error
	}{
		{"a held statement", []*principalStatus{held}, nil, []*principalStatus{held}, nil, nil},
		{"a newer statement from another issuer is not compared", []*principalStatus{held}, nil,
			[]*principalStatus{held, principal("actor-v", "root-f", testPrincipalMethod, 2, 2)}, nil, nil},
		{"a newer statement under another method is not compared", []*principalStatus{held}, nil,
			[]*principalStatus{held, principal("actor-v", "root-v", testOtherMethod, 2, 3)}, nil, nil},
		{"a newer statement about another principal is not compared", []*principalStatus{held}, nil,
			[]*principalStatus{held, principal("actor-f", "root-v", testPrincipalMethod, 2, 4)}, nil, nil},
		{"a newer statement from the same issuer and method", []*principalStatus{held}, nil,
			[]*principalStatus{held, principal("actor-v", "root-v", testPrincipalMethod, 2, 5)}, nil,
			denied("status-sequence-rollback")},
		{"a newer grant statement about another grant is not compared", nil, []*grantStatus{heldGrant},
			nil, []*grantStatus{heldGrant, grant(grantB, "root-v", 2, 21)}, nil},
		{"a newer grant statement from the same issuer and method", nil, []*grantStatus{heldGrant},
			nil, []*grantStatus{heldGrant, grant(grantA, "root-v", 2, 22)}, denied("status-sequence-rollback")},
		{"an unheld statement", []*principalStatus{principal("actor-v", "root-v", testPrincipalMethod, 1, 6)}, nil,
			[]*principalStatus{held}, nil, denied("digest-mismatch")},
		{"every rollback check runs before any holding check",
			[]*principalStatus{principal("actor-f", "root-f", testPrincipalMethod, 1, 7)}, []*grantStatus{heldGrant},
			[]*principalStatus{held}, []*grantStatus{heldGrant, grant(grantA, "root-v", 2, 23)},
			denied("status-sequence-rollback")},
	}
	for _, testCase := range cases {
		bundle := &proofBundle{principalStatus: testCase.carried, grantStatus: testCase.carriedGrants}
		context := &verifierContext{
			principalSnapshot: statusSnapshot[principalStatus]{statements: testCase.snapshot},
			grantSnapshot:     statusSnapshot[grantStatus]{statements: testCase.snapshotGrants},
		}
		if got := validateCarriedStatus(bundle, context); got != testCase.want {
			t.Errorf("%s: got %v, want %v", testCase.name, got, testCase.want)
		}
	}
}

// scratchCorpus writes a one-vector corpus copied from raw-key-chain into a
// temporary directory and returns its manifest path. edit may change the
// vector's manifest entry and the artifact bytes, keyed by manifest path;
// artifact digests are recomputed afterwards.
func scratchCorpus(t *testing.T, edit func(vector map[string]any, files map[string][]byte)) string {
	t.Helper()
	source := filepath.Join("..", "..", "..", "..", "core", "fixtures", "v1")
	manifestBytes, err := os.ReadFile(filepath.Join(source, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus map[string]any
	if err := json.Unmarshal(manifestBytes, &corpus); err != nil {
		t.Fatal(err)
	}
	var vector map[string]any
	for _, entry := range corpus["fixtures"].([]any) {
		if entry.(map[string]any)["name"] == "raw-key-chain" {
			vector = entry.(map[string]any)
		}
	}
	if vector == nil {
		t.Fatal("the corpus has no raw-key-chain vector")
	}
	entries := []string{"proof", "context", "canonical_action", "canonical_body", "expected_result"}
	files := make(map[string][]byte)
	for _, key := range entries {
		path := vector[key].(map[string]any)["path"].(string)
		if files[path], err = os.ReadFile(filepath.Join(source, filepath.FromSlash(path))); err != nil {
			t.Fatal(err)
		}
	}
	edit(vector, files)
	root := t.TempDir()
	for _, key := range entries {
		entry := vector[key].(map[string]any)
		path := entry["path"].(string)
		digest := sha256.Sum256(files[path])
		entry["sha256"] = hex.EncodeToString(digest[:])
		target := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, files[path], 0o644); err != nil {
			t.Fatal(err)
		}
	}
	scratch, err := json.Marshal(map[string]any{
		"protocol_major":  1,
		"adapter_context": corpus["adapter_context"],
		"fixtures":        []any{vector},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "manifest.json")
	if err := os.WriteFile(manifestPath, scratch, 0o644); err != nil {
		t.Fatal(err)
	}
	return manifestPath
}

func entryPath(vector map[string]any, key string) string {
	return vector[key].(map[string]any)["path"].(string)
}

func TestWireAuditRawActionRules(t *testing.T) {
	t.Parallel()
	rawAtDecode := func(vector map[string]any) {
		vector["canonical_action"].(map[string]any)["encoding"] = "raw"
		vector["expected_result"].(map[string]any)["stage"] = "decode"
		vector["expected_decision"] = "denied"
		vector["expected_code"] = "malformed-proof"
	}
	cases := []struct {
		name  string
		edit  func(map[string]any, map[string][]byte)
		valid bool
	}{
		{"a canonical vector", func(map[string]any, map[string][]byte) {}, true},
		{"a raw action that is not CBOR, beside a proof that parses",
			func(vector map[string]any, files map[string][]byte) {
				rawAtDecode(vector)
				files[entryPath(vector, "canonical_action")] = []byte{0xff, 0x00}
			}, true},
		{"an explicit canonical encoding", func(vector map[string]any, _ map[string][]byte) {
			vector["canonical_action"].(map[string]any)["encoding"] = "canonical"
		}, true},
		{"a raw action at another stage", func(vector map[string]any, _ map[string][]byte) {
			vector["canonical_action"].(map[string]any)["encoding"] = "raw"
		}, false},
		{"a raw action beside a proof that does not parse",
			func(vector map[string]any, files map[string][]byte) {
				rawAtDecode(vector)
				files[entryPath(vector, "proof")] = []byte{0xff}
			}, false},
		{"an unknown encoding", func(vector map[string]any, _ map[string][]byte) {
			vector["canonical_action"].(map[string]any)["encoding"] = "hex"
		}, false},
		{"a raw proof", func(vector map[string]any, _ map[string][]byte) {
			vector["proof"].(map[string]any)["encoding"] = "raw"
		}, false},
		{"a canonical action whose body differs from the body artifact",
			func(vector map[string]any, files map[string][]byte) {
				files[entryPath(vector, "canonical_body")] = []byte("another body")
			}, false},
	}
	for _, testCase := range cases {
		digest, err := AuditCorpus(scratchCorpus(t, testCase.edit))
		if testCase.valid && (err != nil || !strings.HasPrefix(digest, "5:")) {
			t.Errorf("%s: got %q, %v; want a 5-artifact digest", testCase.name, digest, err)
		}
		if !testCase.valid && err == nil {
			t.Errorf("%s: the wire audit accepted it", testCase.name)
		}
	}
}

// The semantic audit compares every field, lists each mismatch, and writes a
// report line in the runner contract's format whether or not it fails.
func TestSemanticAuditReportsEveryMismatch(t *testing.T) {
	t.Parallel()
	engine := corpusEngine(t)
	var result Result
	expectFrom := func(code string) func(map[string]any, map[string][]byte) {
		return func(vector map[string]any, files map[string][]byte) {
			result = engine.Verify(
				files[entryPath(vector, "proof")],
				files[entryPath(vector, "canonical_action")],
				files[entryPath(vector, "context")],
			)
			expected := vector["expected_result"].(map[string]any)
			vector["expected_decision"] = string(result.Decision)
			vector["expected_code"] = code
			expected["stage"] = result.Stage
			expected["proof_digest"] = hex.EncodeToString(result.ProofDigest)
			expected["action_digest"] = hex.EncodeToString(result.ActionDigest)
			expected["context_digest"] = hex.EncodeToString(result.ContextDigest)
			expected["plan_digest"] = nil
			if len(result.PlanID) > 0 {
				expected["plan_digest"] = hex.EncodeToString(result.PlanID)
			}
		}
	}
	line := func(mismatched string) string {
		plan := "null"
		if len(result.PlanID) > 0 {
			plan = `"` + hex.EncodeToString(result.PlanID) + `"`
		}
		return fmt.Sprintf(
			`{"name": "raw-key-chain", "implementation": "go-independent", "decision": "%s", "code": "%s", `+
				`"stage": "%s", "proof_digest": "%x", "action_digest": "%x", "context_digest": "%x", `+
				`"plan_digest": %s, "mismatched_fields": [%s]}`+"\n",
			result.Decision, result.Code, result.Stage, result.ProofDigest, result.ActionDigest,
			result.ContextDigest, plan, mismatched,
		)
	}

	manifestPath := scratchCorpus(t, expectFrom("status-issuer-untrusted"))
	reportPath := filepath.Join(t.TempDir(), "report.jsonl")
	if _, err := AuditSemantic(manifestPath, reportPath); err == nil ||
		!strings.Contains(err.Error(), fmt.Sprintf(
			"raw-key-chain: code: got %s, expected status-issuer-untrusted", result.Code,
		)) {
		t.Fatalf("the audit did not report the code mismatch: %v", err)
	}
	report, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(report) != line(`"code"`) {
		t.Fatalf("report line:\n%s\nwant:\n%s", report, line(`"code"`))
	}

	manifestPath = scratchCorpus(t, expectFrom(result.Code))
	digest, err := AuditSemantic(manifestPath, reportPath)
	if err != nil || !strings.HasPrefix(digest, "1:") {
		t.Fatalf("got %q, %v; want a one-vector digest", digest, err)
	}
	if report, err = os.ReadFile(reportPath); err != nil || string(report) != line("") {
		t.Fatalf("report line:\n%s\nwant:\n%s", report, line(""))
	}
}
