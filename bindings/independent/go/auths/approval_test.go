package auths

import (
	"bytes"
	"errors"
	"testing"
)

// editTree decodes data, applies edit, and re-encodes every container, so an
// edit may replace any node with one that carries only its encoding.
func editTree(t *testing.T, data []byte, edit func(root *cborValue)) []byte {
	t.Helper()
	root, err := decodeValue(data)
	if err != nil {
		t.Fatal(err)
	}
	edit(root)
	var clear func(value *cborValue)
	clear = func(value *cborValue) {
		switch value.major {
		case 4:
			value.raw = nil
			for _, child := range value.array {
				clear(child)
			}
		case 5:
			value.raw = nil
			for _, pair := range value.pairs {
				clear(pair.value)
			}
		}
	}
	clear(root)
	return encodeTree(root)
}

// entry returns the value of an integer key of a decoded map.
func entry(t *testing.T, value *cborValue, key uint64) *cborValue {
	t.Helper()
	result, err := mapValue(value, key)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// setEntry replaces the value of an integer key of a decoded map.
func setEntry(t *testing.T, value *cborValue, key uint64, replacement []byte) {
	t.Helper()
	for index := range value.pairs {
		if value.pairs[index].key.uint == key {
			value.pairs[index].value = &cborValue{raw: replacement}
			return
		}
	}
	t.Fatalf("no map key %d", key)
}

func encodeTexts(values ...string) []byte {
	output := encodeCBORHead(4, uint64(len(values)))
	for _, value := range values {
		output = append(output, encodeCBORText(value)...)
	}
	return output
}

func encodeRequirement(k uint64, approvers ...string) []byte {
	output := append(encodeCBORHead(5, 2), 0x00)
	output = append(append(output, encodeTexts(approvers...)...), 0x01)
	return append(output, encodeCBORHead(0, k)...)
}

func encodeArray(items ...[]byte) []byte {
	output := encodeCBORHead(4, uint64(len(items)))
	for _, item := range items {
		output = append(output, item...)
	}
	return output
}

// Splices of approval-2-of-3, whose context requires 2 of 3 approvers, each
// with an approver anchor. A context whose approval configuration is
// inconsistent is malformed-proof at decode.
func TestApprovalContextValidity(t *testing.T) {
	t.Parallel()
	engine := corpusEngine(t)
	proof, action, base := corpusVector(t, "approval-2-of-3")
	decoded := mustDecodeContext(t, base)
	if len(decoded.approvalRequirements) != 1 || len(decoded.approverAnchors) != 4 ||
		decoded.approvalRequirements[0].k != 2 || len(decoded.approvalRequirements[0].approvers) != 3 {
		t.Fatal("the baseline is not one 2-of-3 requirement over four approver anchors")
	}
	approvers := decoded.approvalRequirements[0].approvers
	requirement := func(root *cborValue) *cborValue {
		return entry(t, root, 16).array[0]
	}
	unchanged := editTree(t, base, func(*cborValue) {})
	if !bytes.Equal(unchanged, base) {
		t.Fatal("the baseline context does not re-encode to itself")
	}
	if result := engine.Verify(proof, action, unchanged); result.Decision != Authorized {
		t.Fatalf("the baseline is %s/%s", result.Decision, result.Code)
	}
	cases := []struct {
		name string
		edit func(root *cborValue)
	}{
		{"K above its approver count", func(root *cborValue) {
			setEntry(t, requirement(root), 1, []byte{0x04})
		}},
		{"K of zero", func(root *cborValue) {
			setEntry(t, requirement(root), 1, []byte{0x00})
		}},
		{"K above sixteen", func(root *cborValue) {
			setEntry(t, requirement(root), 1, encodeCBORHead(0, 17))
		}},
		{"an approver without an approver anchor", func(root *cborValue) {
			setEntry(t, requirement(root), 0,
				encodeTexts(append(append([]string(nil), approvers...), "key:sha256:~unanchored")...))
		}},
		{"approvers out of order", func(root *cborValue) {
			setEntry(t, requirement(root), 0, encodeTexts(approvers[1], approvers[0], approvers[2]))
		}},
		{"a repeated requirement", func(root *cborValue) {
			list := entry(t, root, 16)
			list.array = append(list.array, list.array[0])
		}},
		{"an approval limit above its hard maximum", func(root *cborValue) {
			setEntry(t, entry(t, root, 0), 27, encodeCBORHead(0, 129))
		}},
		{"an approver anchor accepting an unaccepted principal method", func(root *cborValue) {
			setEntry(t, entry(t, root, 15).array[0], 1, encodeTexts("raw-key-v1", "zz-unaccepted-v1"))
		}},
		{"an approver anchor naming an unaccepted principal-status method", func(root *cborValue) {
			status := append(encodeCBORHead(5, 3), 0x00, 0x01, 0x01)
			status = append(append(status, encodeCBORText("other-status-v1")...), 0x02, 0x14)
			setEntry(t, entry(t, root, 15).array[0], 4, status)
		}},
		{"approver anchors out of order", func(root *cborValue) {
			anchors := entry(t, root, 15)
			anchors.array[0], anchors.array[1] = anchors.array[1], anchors.array[0]
		}},
		{"a repeated approver anchor", func(root *cborValue) {
			anchors := entry(t, root, 15)
			anchors.array = append([]*cborValue{anchors.array[0]}, anchors.array...)
		}},
		{"an approver anchor window ending before it starts", func(root *cborValue) {
			anchor := entry(t, root, 15).array[0]
			setEntry(t, anchor, 2, encodeCBORHead(0, 101))
		}},
	}
	for _, testCase := range cases {
		requireDecodeFailure(t, testCase.name, engine.Verify(proof, action, editTree(t, base, testCase.edit)))
	}
	many := make([]string, 17)
	for index := range many {
		many[index] = "key:sha256:" + string(rune('A'+index))
	}
	overLimit := []struct {
		name string
		edit func(root *cborValue)
	}{
		{"more requirements than the context limit", func(root *cborValue) {
			setEntry(t, entry(t, root, 0), 29, []byte{0x00})
		}},
		{"more approver anchors than the context limit", func(root *cborValue) {
			setEntry(t, entry(t, root, 0), 28, []byte{0x03})
		}},
		{"seventeen approvers in one requirement", func(root *cborValue) {
			setEntry(t, requirement(root), 0, encodeTexts(many...))
		}},
	}
	for _, testCase := range overLimit {
		result := engine.Verify(proof, action, editTree(t, base, testCase.edit))
		if result.Decision != Denied || result.Code != "resource-limit-exceeded" ||
			result.Stage != stageDecode || len(result.PlanID) != 0 {
			t.Errorf("%s: got %s/%s at %s, want denied/resource-limit-exceeded at decode",
				testCase.name, result.Decision, result.Code, result.Stage)
		}
	}
}

// Proof-carried approvals: repetitions are kept and carry no meaning, and an
// approval above 4096 bytes or with more than four evidence objects is
// resource-limit-exceeded at decode.
func TestApprovalProofBounds(t *testing.T) {
	t.Parallel()
	engine := corpusEngine(t)
	proof, action, context := corpusVector(t, "approval-2-of-3")
	approvals := func(root *cborValue) *cborValue { return entry(t, root, 10) }
	repeated := editTree(t, proof, func(root *cborValue) {
		list := approvals(root)
		list.array = append(list.array, list.array...)
	})
	if result := engine.Verify(repeated, action, context); result.Decision != Authorized {
		t.Errorf("repeated approvals: got %s/%s, want authorized", result.Decision, result.Code)
	}
	reversed := editTree(t, proof, func(root *cborValue) {
		list := approvals(root)
		list.array[0], list.array[1] = list.array[1], list.array[0]
	})
	if result := engine.Verify(reversed, action, context); result.Decision != Authorized {
		t.Errorf("reordered approvals: got %s/%s, want authorized", result.Decision, result.Code)
	}
	withoutOne := editTree(t, proof, func(root *cborValue) {
		list := approvals(root)
		list.array = list.array[:1]
	})
	if result := engine.Verify(withoutOne, action, context); result.Decision != Denied ||
		result.Code != "approval-threshold-not-met" || result.Stage != stageAuthority {
		t.Errorf("one approval: got %s/%s at %s, want denied/approval-threshold-not-met at authority",
			result.Decision, result.Code, result.Stage)
	}
	oversized := editTree(t, proof, func(root *cborValue) {
		envelope := entry(t, approvals(root).array[0], 1)
		setEntry(t, envelope, 1, encodeCBORBytes(bytes.Repeat([]byte{0x01}, 4000)))
	})
	evidence := editTree(t, proof, func(root *cborValue) {
		approval := approvals(root).array[0]
		list := entry(t, approval, 2)
		list.array = []*cborValue{list.array[0], list.array[0], list.array[0], list.array[0], list.array[0]}
	})
	notArray := editTree(t, proof, func(root *cborValue) {
		setEntry(t, root, 10, []byte{0xa0})
	})
	cases := []struct {
		name  string
		proof []byte
		code  string
	}{
		{"an approval above 4096 bytes", oversized, "resource-limit-exceeded"},
		{"five evidence objects in one approval", evidence, "resource-limit-exceeded"},
		{"approvals that are no array", notArray, "malformed-proof"},
	}
	for _, testCase := range cases {
		result := engine.Verify(testCase.proof, action, context)
		if result.Decision != Denied || result.Code != testCase.code || result.Stage != stageDecode ||
			len(result.PlanID) != 0 {
			t.Errorf("%s: got %s/%s at %s, want denied/%s at decode",
				testCase.name, result.Decision, result.Code, result.Stage, testCase.code)
		}
	}
}

// The approval-requirement-v1 handler: a bound is resource-limit-exceeded and
// any other invalid or non-canonical bytes are local-policy-denied.
func TestApprovalRequirementHandler(t *testing.T) {
	t.Parallel()
	a, b, c := "key:a", "key:b", "key:c"
	valid := encodeRequirement(2, a, b, c)
	other := encodeRequirement(1, a)
	first, second := valid, other
	if bytes.Compare(domainHash(12, valid), domainHash(12, other)) > 0 {
		first, second = other, valid
	}
	many := make([]string, 17)
	for index := range many {
		many[index] = "key:" + string(rune('a'+index))
	}
	nonMinimalK := append(append(append(encodeCBORHead(5, 2), 0x00), encodeTexts(a, b)...), 0x01, 0x18, 0x01)
	cases := []struct {
		name  string
		bytes []byte
		code  string
	}{
		{"one requirement", encodeArray(valid), ""},
		{"two requirements in identifier order", encodeArray(first, second), ""},
		{"five requirements", encodeArray(valid, valid, valid, valid, valid), "resource-limit-exceeded"},
		{"seventeen approvers", encodeArray(encodeRequirement(1, many...)), "resource-limit-exceeded"},
		{"no requirement", encodeArray(), "local-policy-denied"},
		{"K above its approver count", encodeArray(encodeRequirement(4, a, b, c)), "local-policy-denied"},
		{"K of zero", encodeArray(encodeRequirement(0, a)), "local-policy-denied"},
		{"approvers out of order", encodeArray(encodeRequirement(1, b, a)), "local-policy-denied"},
		{"a repeated approver", encodeArray(encodeRequirement(1, a, a)), "local-policy-denied"},
		{"requirements out of identifier order", encodeArray(second, first), "local-policy-denied"},
		{"a repeated requirement", encodeArray(valid, valid), "local-policy-denied"},
		{"a non-minimal K", encodeArray(nonMinimalK), "local-policy-denied"},
		{"trailing bytes", append(encodeArray(valid), 0x00), "local-policy-denied"},
		{"not CBOR", []byte{0xff}, "local-policy-denied"},
	}
	for _, testCase := range cases {
		err := evaluateApprovalExtension(criticalExtension{id: approvalExtension, bytes: testCase.bytes})
		code := ""
		var failure semanticFailure
		if errors.As(err, &failure) {
			code = failure.code
		} else if err != nil {
			code = err.Error()
		}
		if code != testCase.code {
			t.Errorf("%s: got %q, want %q", testCase.name, code, testCase.code)
		}
	}
}

// The attenuation law: every parent requirement must be covered by a child
// requirement whose approvers are a subset and whose K is no lower; the child
// may add requirements and may add the extension to a parent without it, but
// may not drop it.
func TestApprovalRequirementLaw(t *testing.T) {
	t.Parallel()
	a, b, c, d := "key:a", "key:b", "key:c", "key:d"
	extension := func(requirements ...[]byte) []criticalExtension {
		ordered := append([][]byte(nil), requirements...)
		for left := range ordered {
			for right := left + 1; right < len(ordered); right++ {
				if bytes.Compare(domainHash(12, ordered[left]), domainHash(12, ordered[right])) > 0 {
					ordered[left], ordered[right] = ordered[right], ordered[left]
				}
			}
		}
		return []criticalExtension{{id: approvalExtension, bytes: encodeArray(ordered...)}}
	}
	parent := extension(encodeRequirement(2, a, b, c))
	accepted := []string{approvalExtension}
	cases := []struct {
		name   string
		child  []criticalExtension
		parent []criticalExtension
		want   bool
	}{
		{"kept byte-identical", parent, parent, true},
		{"narrowed approvers", extension(encodeRequirement(2, a, b)), parent, true},
		{"raised K", extension(encodeRequirement(3, a, b, c)), parent, true},
		{"kept and another added", extension(encodeRequirement(2, a, b, c), encodeRequirement(1, d)), parent, true},
		{"added under a parent without it", parent, nil, true},
		{"widened approvers", extension(encodeRequirement(2, a, b, c, d)), parent, false},
		{"lowered K", extension(encodeRequirement(1, a, b, c)), parent, false},
		{"replaced by an unrelated requirement", extension(encodeRequirement(2, d)), parent, false},
		{"dropped", nil, parent, false},
	}
	for _, testCase := range cases {
		if got := extensionsAttenuate(testCase.child, testCase.parent, accepted); got != testCase.want {
			t.Errorf("%s: got %v, want %v", testCase.name, got, testCase.want)
		}
	}
	if extensionsAttenuate(parent, nil, nil) {
		t.Error("an extension the context does not accept has a law")
	}
}

// Only an issuer the snapshot does not know, or one whose rules have scope
// any, speaks about an approver: own and anchors scopes name trust anchors.
func TestApproverStatusScope(t *testing.T) {
	t.Parallel()
	trust := []statusTrustRule{
		{method: testPrincipalMethod, issuer: "own-issuer", scope: statusScope{kind: statusScopeOwn}},
		{method: testPrincipalMethod, issuer: "listed-issuer",
			scope: statusScope{kind: statusScopeAnchors, anchors: []string{"anchor-v"}}},
		{method: testPrincipalMethod, issuer: "any-issuer", scope: statusScope{kind: statusScopeAny}},
	}
	cases := []struct {
		issuer string
		out    bool
	}{
		{"own-issuer", true},
		{"listed-issuer", true},
		{"any-issuer", false},
		{"unknown-issuer", false},
	}
	for _, testCase := range cases {
		if got := approverOutOfScope(trust, testCase.issuer); got != testCase.out {
			t.Errorf("%s: out of scope %v, want %v", testCase.issuer, got, testCase.out)
		}
	}
}
