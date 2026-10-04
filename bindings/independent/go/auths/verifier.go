package auths

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type verifiedControl struct {
	statement statementReference
	principal string
	controlResult
	err error
}

type participantReport struct {
	principal string
	role      uint64
	claims    []assuranceClaim
	adapter   string
}

// The stage of a portable result: where the first failure occurred, or
// complete when the result is authorized.
const (
	stageDecode           = "decode"
	stageResolve          = "resolve"
	stagePrincipalControl = "principal-control"
	stageAuthority        = "authority"
	stageComplete         = "complete"
)

// reportImplementation names this verifier in a conformance report.
const reportImplementation = "go-independent"

type semanticResult struct {
	decision string
	code     string
	stage    string
	proof    []byte
	context  []byte
	action   []byte
	// plan is nil at stage decode and resolve.
	plan      []byte
	actionIDs [][]byte
	branches  [][]byte
	assurance []participantReport
}

// fieldMismatch is one compared field whose derived value differs from the
// manifest. An absent plan digest is "null".
type fieldMismatch struct {
	field    string
	got      string
	expected string
}

// semanticMismatchError lists every mismatching vector field of one audit.
type semanticMismatchError struct {
	vectors int
	lines   []string
}

func (failure semanticMismatchError) Error() string {
	return fmt.Sprintf(
		"%d vectors disagree with the manifest:\n%s",
		failure.vectors,
		strings.Join(failure.lines, "\n"),
	)
}

// semanticAudit obtains every vector's result through Verify, which alone
// decodes the inputs, and compares it with the manifest. It checks every
// vector before failing, writes the report whether or not any vector
// mismatches, and returns the aggregate semantic digest only when all agree.
func semanticAudit(input manifest, root string, reportPath string) (string, error) {
	engine := &Engine{adapters: input.AdapterContext}
	summary := sha256.New()
	var report bytes.Buffer
	var failure semanticMismatchError
	for _, fixture := range input.Fixtures {
		proofBytes, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(fixture.Proof.Path)))
		if err != nil {
			return "", err
		}
		contextBytes, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(fixture.Context.Path)))
		if err != nil {
			return "", err
		}
		actionBytes, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(fixture.CanonicalAction.Path)))
		if err != nil {
			return "", err
		}
		result := engine.Verify(proofBytes, actionBytes, contextBytes)
		mismatches := compareResult(fixture, result)
		if len(mismatches) > 0 {
			failure.vectors++
		}
		for _, mismatch := range mismatches {
			failure.lines = append(failure.lines, fmt.Sprintf(
				"%s: %s: got %s, expected %s",
				fixture.Name, mismatch.field, mismatch.got, mismatch.expected,
			))
		}
		writeReportLine(&report, fixture.Name, result, mismatches)
		writeSemanticResult(summary, fixture.Name, result)
	}
	if reportPath != "" {
		if err := os.WriteFile(reportPath, report.Bytes(), 0o644); err != nil {
			return "", err
		}
	}
	if failure.vectors > 0 {
		return "", failure
	}
	return fmt.Sprintf("%d:%x", len(input.Fixtures), summary.Sum(nil)), nil
}

// compareResult returns, in report order, each field of the result that
// differs from the fixture's expected decision, code, and result.
func compareResult(fixture fixture, result Result) []fieldMismatch {
	expected := fixture.ExpectedResult
	expectedPlan := "null"
	if expected.PlanDigest != nil {
		expectedPlan = *expected.PlanDigest
	}
	fields := []fieldMismatch{
		{"decision", string(result.Decision), fixture.ExpectedDecision},
		{"code", result.Code, fixture.ExpectedCode},
		{"stage", result.Stage, expected.Stage},
		{"proof_digest", hex.EncodeToString(result.ProofDigest), expected.ProofDigest},
		{"action_digest", hex.EncodeToString(result.ActionDigest), expected.ActionDigest},
		{"context_digest", hex.EncodeToString(result.ContextDigest), expected.ContextDigest},
		{"plan_digest", planDigestText(result.PlanID), expectedPlan},
	}
	var mismatches []fieldMismatch
	for _, field := range fields {
		if field.got != field.expected {
			mismatches = append(mismatches, field)
		}
	}
	return mismatches
}

// planDigestText is the lowercase-hex plan digest, or "null" when absent. No
// hex digest can equal "null".
func planDigestText(plan []byte) string {
	if len(plan) == 0 {
		return "null"
	}
	return hex.EncodeToString(plan)
}

// writeReportLine appends one conformance-report JSON object, keys in the
// runner contract's order.
func writeReportLine(output *bytes.Buffer, name string, result Result, mismatches []fieldMismatch) {
	quote := func(value string) string {
		// Marshalling a Go string cannot fail.
		encoded, _ := json.Marshal(value)
		return string(encoded)
	}
	plan := "null"
	if len(result.PlanID) > 0 {
		plan = quote(hex.EncodeToString(result.PlanID))
	}
	fields := make([]string, 0, len(mismatches))
	for _, mismatch := range mismatches {
		fields = append(fields, quote(mismatch.field))
	}
	members := []string{
		`"name": ` + quote(name),
		`"implementation": ` + quote(reportImplementation),
		`"decision": ` + quote(string(result.Decision)),
		`"code": ` + quote(result.Code),
		`"stage": ` + quote(result.Stage),
		`"proof_digest": ` + quote(hex.EncodeToString(result.ProofDigest)),
		`"action_digest": ` + quote(hex.EncodeToString(result.ActionDigest)),
		`"context_digest": ` + quote(hex.EncodeToString(result.ContextDigest)),
		`"plan_digest": ` + plan,
		`"mismatched_fields": [` + strings.Join(fields, ", ") + `]`,
	}
	output.WriteString("{" + strings.Join(members, ", ") + "}\n")
}

// writeSemanticResult appends one vector's fields to the aggregate semantic
// digest, each followed by a zero byte, in the runner contract's order.
func writeSemanticResult(summary interface{ Write([]byte) (int, error) }, name string, result Result) {
	writeField := func(value string) {
		summary.Write([]byte(value))
		summary.Write([]byte{0})
	}
	writeBytes := func(value []byte) {
		writeField(hex.EncodeToString(value))
	}
	writeField(name)
	writeField(string(result.Decision))
	writeField(result.Code)
	writeField(result.Stage)
	writeBytes(result.ProofDigest)
	writeBytes(result.ContextDigest)
	writeBytes(result.ActionDigest)
	writeBytes(result.PlanID)
	for _, id := range result.ActionIDs {
		writeBytes(id)
	}
	writeField("|")
	for _, branch := range result.AuthorizedBranches {
		writeBytes(branch)
	}
	writeField("|")
	for _, report := range result.Assurance {
		writeField(report.Principal)
		writeField(fmt.Sprintf("%d", report.Role))
		writeField(report.Adapter)
		claims := append([]AssuranceClaim(nil), report.Claims...)
		sort.Slice(claims, func(i, j int) bool {
			if claims[i].Kind != claims[j].Kind {
				return claims[i].Kind < claims[j].Kind
			}
			if claims[i].ObservedAt == nil || claims[j].ObservedAt == nil {
				return claims[i].ObservedAt == nil && claims[j].ObservedAt != nil
			}
			return *claims[i].ObservedAt < *claims[j].ObservedAt
		})
		for _, claim := range claims {
			writeField(claim.Kind)
			if claim.ObservedAt == nil {
				writeField("-")
			} else {
				writeField(fmt.Sprintf("%d", *claim.ObservedAt))
			}
		}
		writeField(";")
	}
	writeField("\n")
}

func verifySemantic(
	proofBytes []byte,
	contextBytes []byte,
	actionBytes []byte,
	adapters adapterContext,
) semanticResult {
	result := semanticResult{
		proof:   sha256Bytes(proofBytes),
		action:  sha256Bytes(actionBytes),
		context: domainHash(9, contextBytes),
	}
	context, err := decodeContext(contextBytes)
	if err != nil {
		result.stage, result.decision, result.code = stageDecode, "denied", "malformed-proof"
		if errors.Is(err, errContextLimit) {
			result.code = "resource-limit-exceeded"
		}
		return result
	}
	// The canonical action is bounded and decoded before the proof is read.
	action, err := decodeBoundedCanonicalAction(actionBytes, context.limits)
	if err != nil {
		return failedResult(result, stageDecode, err)
	}
	bundle, err := decodeBundle(proofBytes, context.limits)
	if err != nil {
		return failedResult(result, stageDecode, err)
	}
	// A decode or resolve result carries no plan digest, so the plan is
	// reported only once every reference has resolved.
	plan := domainHash(3, bundle.plan.raw)
	if context.composition.expectedPlan != nil &&
		!bytes.Equal(context.composition.expectedPlan, plan) {
		return failedResult(result, stageResolve, denied("composition-requirement-not-met"))
	}
	resolved, err := resolveReferences(bundle, context, plan)
	if err != nil {
		return failedResult(result, stageResolve, err)
	}
	result.plan = plan
	controls, err := verifyPrincipalControl(bundle, context, adapters, resolved)
	if err != nil {
		return failedResult(result, stagePrincipalControl, err)
	}
	actionIDs, branches, assurance, err := verifyAuthority(bundle, controls, context, *action, adapters)
	if err != nil {
		return failedResult(result, stageAuthority, err)
	}
	result.stage = stageComplete
	result.decision = "authorized"
	result.code = "authorized"
	result.actionIDs = actionIDs
	result.branches = branches
	result.assurance = assurance
	return result
}

func failedResult(result semanticResult, stage string, err error) semanticResult {
	result.stage = stage
	var failure semanticFailure
	if errors.As(err, &failure) {
		result.decision = failure.decision
		result.code = failure.code
	} else {
		result.decision = "denied"
		result.code = "malformed-proof"
	}
	return result
}

func sha256Bytes(value []byte) []byte {
	digest := sha256.Sum256(value)
	return digest[:]
}

// resolvedReferences is what reference resolution hands principal control:
// the proof's evidence objects and control bindings, keyed for lookup.
type resolvedReferences struct {
	evidenceByID map[string]*evidenceObject
	bindings     map[string]*controlBinding
}

// resolveReferences runs reference resolution, from grant identifiers through
// the check on proof-carried status statements. planID is the recomputed
// plan identifier, already checked against the context's expected plan.
func resolveReferences(
	bundle *proofBundle,
	context *verifierContext,
	planID []byte,
) (*resolvedReferences, error) {
	grants := make(map[string]*signedGrant, len(bundle.grants))
	for _, grant := range bundle.grants {
		key := digestKey(grant.id)
		if grants[key] != nil {
			return nil, denied("duplicate-object")
		}
		grants[key] = grant
	}
	actionsByID := make(map[string]*signedAction, len(bundle.actions))
	actionsByRef := make(map[string]*signedAction, len(bundle.actions))
	for _, action := range bundle.actions {
		if !bytes.Equal(action.planID, planID) {
			return nil, denied("plan-action-mismatch")
		}
		idKey := digestKey(action.id)
		refKey := digestKey(action.proofRef)
		if actionsByID[idKey] != nil || actionsByRef[refKey] != nil {
			return nil, denied("duplicate-object")
		}
		actionsByID[idKey] = action
		actionsByRef[refKey] = action
	}
	leaves := collectLeaves(bundle.plan)
	if len(leaves) != len(bundle.actions) {
		return nil, denied("missing-reference")
	}
	for _, leaf := range leaves {
		if actionsByRef[digestKey(leaf)] == nil {
			return nil, denied("missing-reference")
		}
	}
	evidenceByID := make(map[string]*evidenceObject, len(bundle.evidence))
	for _, object := range bundle.evidence {
		key := digestKey(object.id)
		if evidenceByID[key] != nil {
			return nil, denied("duplicate-object")
		}
		evidenceByID[key] = object
	}
	principalStatusByID := make(map[string]*principalStatus)
	for _, status := range context.principalSnapshot.statements {
		key := digestKey(status.id)
		if principalStatusByID[key] != nil {
			return nil, denied("duplicate-object")
		}
		principalStatusByID[key] = status
	}
	grantStatusByID := make(map[string]*grantStatus)
	for _, status := range context.grantSnapshot.statements {
		key := digestKey(status.id)
		if grantStatusByID[key] != nil {
			return nil, denied("duplicate-object")
		}
		grantStatusByID[key] = status
	}
	bindings := make(map[string]*controlBinding, len(bundle.bindings))
	for _, binding := range bundle.bindings {
		key := binding.statement.key()
		if bindings[key] != nil {
			return nil, denied("duplicate-object")
		}
		exists := false
		switch binding.statement.kind {
		case 0:
			exists = grants[digestKey(binding.statement.id)] != nil
		case 1:
			exists = actionsByID[digestKey(binding.statement.id)] != nil
		case 2:
			exists = principalStatusByID[digestKey(binding.statement.id)] != nil
		case 3:
			exists = grantStatusByID[digestKey(binding.statement.id)] != nil
		}
		if !exists {
			return nil, denied("missing-reference")
		}
		for _, id := range binding.evidence {
			if evidenceByID[digestKey(id)] == nil {
				return nil, denied("missing-reference")
			}
		}
		bindings[key] = binding
	}
	usedGrants := make(map[string]bool)
	for _, action := range bundle.actions {
		seen := make(map[string]bool)
		cursor := action.terminalGrant
		for cursor != nil {
			key := digestKey(cursor)
			if seen[key] {
				return nil, denied("reference-cycle")
			}
			seen[key] = true
			grant := grants[key]
			if grant == nil {
				return nil, denied("missing-reference")
			}
			usedGrants[key] = true
			cursor = grant.parent
		}
	}
	if len(usedGrants) != len(grants) {
		return nil, denied("unused-critical-evidence")
	}
	attachmentDigests := make(map[string]bool)
	for _, attachment := range bundle.attachments {
		key := digestKey(attachment.digest)
		if attachmentDigests[key] {
			return nil, denied("duplicate-attachment")
		}
		attachmentDigests[key] = true
	}
	if err := validateCarriedStatus(bundle, context); err != nil {
		return nil, err
	}
	return &resolvedReferences{evidenceByID: evidenceByID, bindings: bindings}, nil
}

// verifyPrincipalControl runs principal control over resolved references. A
// statement's control failure is stored on it for the branch that needs it;
// only resource exhaustion and unconsumed evidence end verification here.
func verifyPrincipalControl(
	bundle *proofBundle,
	context *verifierContext,
	adapters adapterContext,
	resolved *resolvedReferences,
) ([]verifiedControl, error) {
	evidenceByID := resolved.evidenceByID
	bindings := resolved.bindings
	// Principal control starts by requiring the executable registry and
	// configuration, after every reference has resolved.
	if !bytes.Equal(context.registryManifest, bytes.Repeat([]byte{0x37}, 32)) {
		return nil, denied("registry-manifest-mismatch")
	}
	localConfiguration, err := hex.DecodeString(adapters.Configuration)
	if err != nil || len(localConfiguration) != 32 ||
		!bytes.Equal(context.configuration, localConfiguration) {
		return nil, denied("verifier-configuration-mismatch")
	}

	type signedInput struct {
		reference   statementReference
		principal   string
		signature   signatureEnvelope
		profile     profile
		statement   []byte
		objectKind  uint16
		purpose     uint64
		signingTime uint64
	}
	inputs := make([]signedInput, 0)
	sortedGrants := append([]*signedGrant(nil), bundle.grants...)
	sort.Slice(sortedGrants, func(i, j int) bool {
		return bytes.Compare(sortedGrants[i].id, sortedGrants[j].id) < 0
	})
	for _, grant := range sortedGrants {
		inputs = append(inputs, signedInput{
			reference: statementReference{kind: 0, id: grant.id},
			principal: grant.issuer, signature: grant.signature,
			profile: grant.profile, statement: grant.statement.raw,
			objectKind: 1, purpose: 0, signingTime: grant.notBefore,
		})
	}
	sortedActions := append([]*signedAction(nil), bundle.actions...)
	sort.Slice(sortedActions, func(i, j int) bool {
		return bytes.Compare(sortedActions[i].id, sortedActions[j].id) < 0
	})
	for _, action := range sortedActions {
		inputs = append(inputs, signedInput{
			reference: statementReference{kind: 1, id: action.id},
			principal: action.actor, signature: action.signature,
			profile: action.profile, statement: action.envelope.raw,
			objectKind: 2, purpose: 1, signingTime: action.notBefore,
		})
	}
	for _, status := range context.principalSnapshot.statements {
		inputs = append(inputs, signedInput{
			reference: statementReference{kind: 2, id: status.id},
			principal: status.issuer, signature: status.signature,
			statement: status.statement.raw, objectKind: 3,
			purpose: 2, signingTime: status.observedAt,
		})
	}
	for _, status := range context.grantSnapshot.statements {
		inputs = append(inputs, signedInput{
			reference: statementReference{kind: 3, id: status.id},
			principal: status.issuer, signature: status.signature,
			statement: status.statement.raw, objectKind: 4,
			purpose: 2, signingTime: status.observedAt,
		})
	}
	controls := make([]verifiedControl, 0, len(inputs))
	consumed := make(map[string]bool)
	var work uint64
	for _, input := range inputs {
		binding := bindings[input.reference.key()]
		if binding == nil {
			controls = append(controls, verifiedControl{
				statement: input.reference,
				principal: input.principal,
				err:       indeterminate("missing-principal-evidence"),
			})
			continue
		}
		bound := make([]*evidenceObject, 0, len(binding.evidence))
		for _, id := range binding.evidence {
			bound = append(bound, evidenceByID[digestKey(id)])
			consumed[digestKey(id)] = true
		}
		preimage := signingPreimage(
			input.objectKind, input.profile, input.statement, input.signature.descriptor.raw,
		)
		control, err := verifyControl(
			input.signature.descriptor.method,
			input.principal,
			input.signature.descriptor,
			input.purpose,
			input.signingTime,
			preimage,
			bound,
			context,
			adapters,
		)
		if err != nil {
			controls = append(controls, verifiedControl{
				statement: input.reference, principal: input.principal, err: err,
			})
			continue
		}
		message := preimage
		if control.signatureMessage != nil {
			message = control.signatureMessage
		}
		if !verifySignature(
			input.signature.descriptor.suite,
			control.key,
			message,
			input.signature.signature,
		) {
			controls = append(controls, verifiedControl{
				statement: input.reference,
				principal: input.principal,
				err:       denied("invalid-signature"),
			})
			continue
		}
		suiteWork := uint64(100)
		if input.signature.descriptor.suite == "p256-sha256-v1" {
			suiteWork = 250
		}
		if work > context.limits[26] || control.work > context.limits[26]-work {
			return nil, denied("resource-limit-exceeded")
		}
		work += control.work
		if work > context.limits[26] || suiteWork > context.limits[26]-work {
			return nil, denied("resource-limit-exceeded")
		}
		work += suiteWork
		for _, id := range control.consumed {
			consumed[digestKey(id)] = true
		}
		controls = append(controls, verifiedControl{
			statement: input.reference, principal: input.principal, controlResult: control,
		})
	}
	for _, id := range context.principalSnapshot.checkpoints {
		consumed[digestKey(id)] = true
	}
	for _, id := range context.grantSnapshot.checkpoints {
		consumed[digestKey(id)] = true
	}
	for _, object := range bundle.evidence {
		if !consumed[digestKey(object.id)] {
			return nil, denied("unused-critical-evidence")
		}
	}
	return controls, nil
}

// validateCarriedStatus checks proof-carried status statements in two passes,
// each over the carried principal-status statements and then the carried
// grant-status statements, in proof order. The first pass rejects a statement
// older than a snapshot statement with the same subject, method, and issuer:
// a sequence number orders one issuer's statements under one method, so a
// statement from another issuer or under another method is never compared.
// The second pass rejects a statement the snapshot does not hold. Every
// rollback check runs before any holding check.
func validateCarriedStatus(bundle *proofBundle, context *verifierContext) error {
	for _, carried := range bundle.principalStatus {
		for _, current := range context.principalSnapshot.statements {
			if current.principal == carried.principal && current.method == carried.method &&
				current.issuer == carried.issuer && current.sequence > carried.sequence {
				return denied("status-sequence-rollback")
			}
		}
	}
	for _, carried := range bundle.grantStatus {
		for _, current := range context.grantSnapshot.statements {
			if bytes.Equal(current.grantID, carried.grantID) && current.method == carried.method &&
				current.issuer == carried.issuer && current.sequence > carried.sequence {
				return denied("status-sequence-rollback")
			}
		}
	}
	for _, carried := range bundle.principalStatus {
		held := false
		for _, current := range context.principalSnapshot.statements {
			if bytes.Equal(carried.statement.raw, current.statement.raw) &&
				bytes.Equal(carried.signature.signature, current.signature.signature) {
				held = true
				break
			}
		}
		if !held {
			return denied("digest-mismatch")
		}
	}
	for _, carried := range bundle.grantStatus {
		held := false
		for _, current := range context.grantSnapshot.statements {
			if bytes.Equal(carried.statement.raw, current.statement.raw) &&
				bytes.Equal(carried.signature.signature, current.signature.signature) {
				held = true
				break
			}
		}
		if !held {
			return denied("digest-mismatch")
		}
	}
	return nil
}

func collectLeaves(plan *planNode) [][]byte {
	if plan.kind == 0 {
		return [][]byte{plan.proofRef}
	}
	var result [][]byte
	for _, child := range plan.children {
		result = append(result, collectLeaves(child)...)
	}
	return result
}

func verifyAuthority(
	bundle *proofBundle,
	controls []verifiedControl,
	context *verifierContext,
	canonical canonicalAction,
	adapters adapterContext,
) ([][]byte, [][]byte, []participantReport, error) {
	// Action binding runs once, before any branch: the carried body, each
	// signed action in proof order, the attachments, then the profile policy.
	if bundle.canonicalBody != nil && !bytes.Equal(bundle.canonicalBody, canonical.body) {
		return nil, nil, nil, denied("action-body-mismatch")
	}
	expectedBody := sha256Bytes(canonical.body)
	first := bundle.actions[0]
	for _, action := range bundle.actions {
		if !equalProfile(action.profile, canonical.profile) ||
			action.mediaType != canonical.mediaType ||
			!bytes.Equal(action.bodyDigest, expectedBody) ||
			!equalPermission(action.permission, canonical.permission) ||
			!equalBudget(action.budget, canonical.budget) {
			return nil, nil, nil, denied("action-body-mismatch")
		}
		if !profileContains(context.profiles, action.profile) {
			return nil, nil, nil, indeterminate("unsupported-profile")
		}
		if action.audience != context.expectedAudience {
			return nil, nil, nil, denied("audience-mismatch")
		}
		if !bytes.Equal(action.challenge, context.expectedChallenge) {
			return nil, nil, nil, denied("challenge-mismatch")
		}
		if context.evaluationTime < action.notBefore || context.evaluationTime > action.expiresAt {
			return nil, nil, nil, denied("action-outside-validity")
		}
		if action.channel != context.channelPolicy {
			return nil, nil, nil, denied("local-policy-denied")
		}
		if !sharedAction(first, action) {
			return nil, nil, nil, denied("plan-action-mismatch")
		}
		if err := evaluateCriticalExtensions(action.extensions, context.extensions); err != nil {
			return nil, nil, nil, err
		}
		if err := validateObservationAttachments(action); err != nil {
			return nil, nil, nil, err
		}
	}
	if err := validateAttachments(bundle, canonical, context); err != nil {
		return nil, nil, nil, err
	}
	if !containsText(context.profilePolicies, context.profilePolicy) ||
		context.profilePolicy != "exact-v1" {
		return nil, nil, nil, indeterminate("unsupported-profile-policy")
	}
	actionByRef := make(map[string]*signedAction)
	grantByID := make(map[string]*signedGrant)
	controlByStatement := make(map[string]verifiedControl)
	for _, action := range bundle.actions {
		actionByRef[digestKey(action.proofRef)] = action
	}
	for _, grant := range bundle.grants {
		grantByID[digestKey(grant.id)] = grant
	}
	for _, control := range controls {
		controlByStatement[control.statement.key()] = control
	}
	var authorizedBranches [][]byte
	var actionIDs [][]byte
	var reports []participantReport
	approvals := newApprovalEvaluator(bundle, canonical, context, adapters, controlByStatement)
	branch := func(reference []byte) branchResult {
		action := actionByRef[digestKey(reference)]
		if action == nil {
			return branchResult{err: denied("missing-reference")}
		}
		chain := make([]*signedGrant, 0)
		cursor := action.terminalGrant
		for cursor != nil {
			grant := grantByID[digestKey(cursor)]
			if grant == nil {
				return branchResult{err: denied("missing-reference")}
			}
			chain = append(chain, grant)
			cursor = grant.parent
		}
		for left, right := 0, len(chain)-1; left < right; left, right = left+1, right-1 {
			chain[left], chain[right] = chain[right], chain[left]
		}
		root := action.actor
		rootReference := statementReference{kind: 1, id: action.id}
		if len(chain) > 0 {
			root = chain[0].issuer
			rootReference = statementReference{kind: 0, id: chain[0].id}
		}
		rootControl, ok := controlByStatement[rootReference.key()]
		if !ok {
			return branchResult{err: indeterminate("missing-principal-evidence")}
		}
		if rootControl.err != nil {
			return branchResult{err: rootControl.err}
		}
		var firstFailure error
		for _, anchor := range context.anchors {
			if anchor.principal != root {
				continue
			}
			branchReports, err := verifyFromAnchor(
				action, chain, rootControl, anchor, context, controlByStatement,
			)
			if err == nil {
				err = observationStage{
					chain: chain, root: anchor.principal, action: action,
					canonical: canonical, context: context, adapters: adapters,
				}.evaluate()
			}
			// Grant-carried approval requirements are the last step of each
			// anchor's attempt. Every limit reached here is this attempt's
			// failure, which the plan combines.
			if err == nil {
				err = branchApprovals(approvals, chain)
			}
			if err == nil {
				return branchResult{actionID: action.id, reports: branchReports}
			}
			if firstFailure == nil {
				firstFailure = err
			}
		}
		if firstFailure == nil {
			firstFailure = denied("untrusted-root")
		}
		return branchResult{err: firstFailure}
	}
	outcome := evaluatePlan(bundle.plan, branch, &authorizedBranches, &actionIDs, &reports)
	if outcome.err != nil {
		return nil, nil, nil, outcome.err
	}
	sort.Slice(actionIDs, func(i, j int) bool { return bytes.Compare(actionIDs[i], actionIDs[j]) < 0 })
	actionIDs = uniqueDigests(actionIDs)
	sort.Slice(authorizedBranches, func(i, j int) bool {
		return bytes.Compare(authorizedBranches[i], authorizedBranches[j]) < 0
	})
	authorizedBranches = uniqueDigests(authorizedBranches)
	sort.Slice(reports, func(i, j int) bool {
		if reports[i].role != reports[j].role {
			return reports[i].role < reports[j].role
		}
		return reports[i].principal < reports[j].principal
	})
	reports = uniqueReports(reports)
	actors := make(map[string]struct{})
	roots := make(map[string]struct{})
	for _, report := range reports {
		switch report.role {
		case 0:
			roots[report.principal] = struct{}{}
		case 2:
			actors[report.principal] = struct{}{}
		}
	}
	if uint64(len(authorizedBranches)) < context.composition.minimumAuthorizedBranches ||
		uint64(len(actors)) < context.composition.minimumDistinctActors ||
		uint64(len(roots)) < context.composition.minimumDistinctRoots {
		return nil, nil, nil, denied("composition-requirement-not-met")
	}
	// The trusted context's approval requirements, in ascending identifier
	// order, after the composition minimums hold.
	if err := approvals.evaluateList(context.approvalRequirements); err != nil {
		if errors.Is(err, errApprovalEvaluations) {
			return nil, nil, nil, denied("resource-limit-exceeded")
		}
		return nil, nil, nil, err
	}
	return actionIDs, authorizedBranches, reports, nil
}

func validateAttachments(
	bundle *proofBundle,
	canonical canonicalAction,
	context *verifierContext,
) error {
	descriptors := bundle.actions[0].attachments
	if !equalAttachmentDescriptors(descriptors, bundle.attachments) {
		return denied("unused-critical-attachment")
	}
	seen := make(map[string]bool)
	for _, descriptor := range descriptors {
		key := digestKey(descriptor.digest)
		if seen[key] {
			return denied("duplicate-attachment")
		}
		seen[key] = true
	}
	detached := make(map[string]detachedAttachment)
	var total uint64
	for _, attachment := range canonical.detached {
		key := digestKey(attachment.digest)
		if _, duplicate := detached[key]; duplicate {
			return denied("duplicate-attachment")
		}
		detached[key] = attachment
		if uint64(len(attachment.bytes)) > ^uint64(0)-total {
			return denied("resource-limit-exceeded")
		}
		total += uint64(len(attachment.bytes))
	}
	if total > context.limits[14] {
		return denied("resource-limit-exceeded")
	}
	for _, descriptor := range descriptors {
		attachment, ok := detached[digestKey(descriptor.digest)]
		if !ok {
			if descriptor.required {
				return denied("attachment-missing")
			}
			continue
		}
		if uint64(len(attachment.bytes)) != descriptor.byteLength {
			return denied("attachment-length-mismatch")
		}
		digest := sha256.Sum256(attachment.bytes)
		if !bytes.Equal(digest[:], descriptor.digest) {
			return denied("attachment-digest-mismatch")
		}
		if descriptor.encrypted && !descriptor.opaqueAllowed {
			return denied("opaque-attachment-not-allowed")
		}
	}
	for key := range detached {
		if !seen[key] {
			return denied("unused-critical-attachment")
		}
	}
	return nil
}

func sharedAction(left, right *signedAction) bool {
	return equalProfile(left.profile, right.profile) &&
		left.mediaType == right.mediaType &&
		bytes.Equal(left.bodyDigest, right.bodyDigest) &&
		equalPermission(left.permission, right.permission) &&
		equalBudget(left.budget, right.budget) &&
		left.audience == right.audience &&
		bytes.Equal(left.challenge, right.challenge) &&
		left.notBefore == right.notBefore &&
		left.expiresAt == right.expiresAt &&
		bytes.Equal(left.planID, right.planID) &&
		left.channel == right.channel &&
		equalAttachmentDescriptors(left.attachments, right.attachments) &&
		extensionSliceEqual(left.extensions, right.extensions)
}

func equalAttachmentDescriptors(left, right []attachmentDescriptor) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !bytes.Equal(left[index].raw, right[index].raw) {
			return false
		}
	}
	return true
}

func stringSliceEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func extensionSliceEqual(left, right []criticalExtension) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].id != right[index].id || !bytes.Equal(left[index].bytes, right[index].bytes) {
			return false
		}
	}
	return true
}

func findExtension(extensions []criticalExtension, id string) *criticalExtension {
	for index := range extensions {
		if extensions[index].id == id {
			return &extensions[index]
		}
	}
	return nil
}

// extensionsAttenuate is the critical-extension delegation relation: every
// parent identifier is present in the child and its law accepts the pair; an
// identifier only the child carries is accepted only when its law accepts
// adding it.
func extensionsAttenuate(child, parent []criticalExtension, accepted []string) bool {
	for index := range parent {
		retained := findExtension(child, parent[index].id)
		if retained == nil || !extensionLaw(parent[index].id, retained, &parent[index], accepted) {
			return false
		}
	}
	for index := range child {
		if findExtension(parent, child[index].id) == nil &&
			!extensionLaw(child[index].id, &child[index], nil, accepted) {
			return false
		}
	}
	return true
}

// extensionLaw applies the attenuation law of one identifier; nil is an
// absent extension. An identifier the context does not accept, or without a
// handler, has no law.
func extensionLaw(id string, child, parent *criticalExtension, accepted []string) bool {
	if child == nil || !containsText(accepted, id) {
		return false
	}
	switch id {
	case "exact-marker-v1":
		return parent != nil && bytes.Equal(child.bytes, parent.bytes)
	case boundedPolicyExtension:
		return boundedPolicyLaw(child, parent)
	case approvalExtension:
		return approvalLaw(child, parent)
	case observationExtension:
		childRequirements, err := decodeRequirements(child.bytes)
		if err != nil {
			return false
		}
		if parent == nil {
			return true
		}
		parentRequirements, err := decodeRequirements(parent.bytes)
		if err != nil {
			return false
		}
		return requirementsAttenuate(childRequirements, parentRequirements)
	default:
		return false
	}
}

func evaluateCriticalExtensions(extensions []criticalExtension, accepted []string) error {
	for _, extension := range extensions {
		if !containsText(accepted, extension.id) {
			return denied("critical-extension-unknown")
		}
		if extension.id == observationExtension {
			if err := evaluateObservationExtension(extension); err != nil {
				return err
			}
			continue
		}
		if extension.id == boundedPolicyExtension {
			if err := evaluateBoundedPolicyExtension(extension); err != nil {
				return err
			}
			continue
		}
		if extension.id == approvalExtension {
			if err := evaluateApprovalExtension(extension); err != nil {
				return err
			}
			continue
		}
		if extension.id != "exact-marker-v1" {
			return indeterminate("unsupported-critical-extension")
		}
		if !bytes.Equal(extension.bytes, []byte{1}) {
			return denied("local-policy-denied")
		}
	}
	return nil
}

type branchResult struct {
	actionID []byte
	reports  []participantReport
	err      error
}

func evaluatePlan(
	plan *planNode,
	branch func([]byte) branchResult,
	authorizedBranches *[][]byte,
	actionIDs *[][]byte,
	reports *[]participantReport,
) branchResult {
	if plan.kind == 0 {
		result := branch(plan.proofRef)
		if result.err == nil {
			*authorizedBranches = append(*authorizedBranches, plan.proofRef)
			*actionIDs = append(*actionIDs, result.actionID)
			*reports = append(*reports, result.reports...)
		}
		return result
	}
	results := make([]branchResult, 0, len(plan.children))
	for _, child := range plan.children {
		results = append(results, evaluatePlan(child, branch, authorizedBranches, actionIDs, reports))
	}
	canonicalFailure := func(decision string) error {
		var candidates []semanticFailure
		for _, result := range results {
			var failure semanticFailure
			if errors.As(result.err, &failure) && failure.decision == decision {
				candidates = append(candidates, failure)
			}
		}
		sort.Slice(candidates, func(left, right int) bool {
			return candidates[left].code < candidates[right].code
		})
		if len(candidates) == 0 {
			return nil
		}
		return candidates[0]
	}
	switch plan.kind {
	case 1:
		if failure := canonicalFailure("denied"); failure != nil {
			return branchResult{err: failure}
		}
		return branchResult{err: canonicalFailure("indeterminate")}
	case 2:
		for _, result := range results {
			if result.err == nil {
				return result
			}
		}
		if failure := canonicalFailure("indeterminate"); failure != nil {
			return branchResult{err: failure}
		}
		return branchResult{err: canonicalFailure("denied")}
	case 3:
		authorized := 0
		indeterminateCount := 0
		for _, result := range results {
			if result.err == nil {
				authorized++
				continue
			}
			var failure semanticFailure
			errors.As(result.err, &failure)
			if failure.decision == "indeterminate" {
				indeterminateCount++
			}
		}
		if uint64(authorized) >= plan.k {
			return branchResult{}
		}
		if uint64(authorized+indeterminateCount) >= plan.k {
			failure := canonicalFailure("indeterminate")
			if failure == nil {
				failure = indeterminate("external-fact-unavailable")
			}
			return branchResult{err: failure}
		}
		failure := canonicalFailure("denied")
		if failure == nil {
			failure = denied("authorization-plan-invalid")
		}
		return branchResult{err: failure}
	default:
		return branchResult{err: denied("authorization-plan-invalid")}
	}
}

func verifyFromAnchor(
	action *signedAction,
	chain []*signedGrant,
	rootControl verifiedControl,
	anchor *trustAnchor,
	context *verifierContext,
	controls map[string]verifiedControl,
) ([]participantReport, error) {
	method := action.signature.descriptor.method
	if len(chain) > 0 {
		method = chain[0].signature.descriptor.method
	}
	if !containsText(anchor.methods, method) || anchor.assurance != context.assuranceID {
		return nil, denied("untrusted-root")
	}
	// Status runs before resource and attenuation checks, and sees only the
	// statements in scope for this anchor. Every grant subject is checked
	// under the anchor's policy: by chain linkage the subjects are every
	// issuer after the root and the actor.
	if err := checkPrincipalStatus(
		anchor.status, anchor.principal, statusRequired, anchor, context, controls,
	); err != nil {
		return nil, err
	}
	for _, grant := range chain {
		if err := checkGrantStatus(grant.status, grant.id, anchor, context, controls); err != nil {
			return nil, err
		}
		if err := checkPrincipalStatus(
			anchor.status, grant.subject, statusRevocationList, anchor, context, controls,
		); err != nil {
			return nil, err
		}
	}
	if !containsText(context.resourceMatchers, context.resourceMatcher) ||
		context.resourceMatcher != "uri-namespace-v1" {
		return nil, indeterminate("unsupported-resource-matcher")
	}
	// Every grant permission, root to terminal, and then the action's
	// permission must name a resource inside one of the anchor's namespaces.
	for _, grant := range chain {
		for _, granted := range grant.perms {
			if !insideAnchorNamespace(anchor, granted.resource) {
				return nil, denied("resource-namespace-mismatch")
			}
		}
	}
	if !insideAnchorNamespace(anchor, action.permission.resource) {
		return nil, denied("resource-namespace-mismatch")
	}
	if err := validateBudgetChain(anchor, chain, action, context); err != nil {
		return nil, err
	}
	authority := effectiveAuthority{
		subject: anchor.principal, allowedProfiles: anchor.profiles,
		permissions: anchor.permissions, notBefore: anchor.notBefore, expiresAt: anchor.expiresAt,
		audiences: anchor.audiences, constraint: constraint{kind: 0},
		budget: anchor.budget, remainingDepth: anchor.maxDepth,
		assurance: anchor.assurance, status: anchor.status,
	}
	reports := make([]participantReport, 0)
	if len(chain) == 0 {
		if rootControl.err != nil {
			return nil, rootControl.err
		}
		reports = append(reports, report(rootControl, 0))
	}
	for index, grant := range chain {
		if index > 0 {
			if err := requireParentRequirements(chain[index-1], grant); err != nil {
				return nil, err
			}
		}
		if err := authority.delegate(grant, context.extensions); err != nil {
			return nil, err
		}
		control, ok := controls[statementReference{kind: 0, id: grant.id}.key()]
		if !ok {
			return nil, indeterminate("missing-principal-evidence")
		}
		if control.err != nil {
			return nil, control.err
		}
		role := uint64(1)
		if index == 0 {
			role = 0
		}
		reports = append(reports, report(control, role))
		if err := evaluateCriticalExtensions(grant.extensions, context.extensions); err != nil {
			return nil, err
		}
	}
	if err := authority.authorizes(action, profileContains(context.budgetFreeProfiles, action.profile)); err != nil {
		return nil, err
	}
	actionControl, ok := controls[statementReference{kind: 1, id: action.id}.key()]
	if !ok {
		return nil, indeterminate("missing-principal-evidence")
	}
	if actionControl.err != nil {
		return nil, actionControl.err
	}
	reports = append(reports, report(actionControl, 2))
	for _, participant := range reports {
		for _, claim := range participant.claims {
			if !containsText(context.assuranceClaims, claim.kind) {
				return nil, indeterminate("unsupported-assurance-claim")
			}
		}
	}
	if !assuranceSatisfied(context.assurance, reports, context.evaluationTime) {
		return nil, indeterminate("assurance-requirement-not-met")
	}
	return reports, nil
}

func requireBudgetAlgebra(value *budget, context *verifierContext) error {
	if value == nil {
		return nil
	}
	if !containsText(context.budgetAlgebras, value.algebra) ||
		value.algebra != "numeric-ceiling-v1" {
		return indeterminate("unsupported-budget-algebra")
	}
	return nil
}

func insideAnchorNamespace(anchor *trustAnchor, resource string) bool {
	for _, namespace := range anchor.namespaces {
		if uriNamespaceMatches(namespace, resource) {
			return true
		}
	}
	return false
}

// validateBudgetChain compares every bounded ceiling before the delegation
// walk: each grant under a bounded parent, then the action's request under a
// bounded terminal ceiling. An algebra is resolved only where a bounded
// ceiling is compared, and the parent's algebra rejects a value in any other
// algebra as invalid input, which is local-policy-denied.
func validateBudgetChain(
	anchor *trustAnchor,
	chain []*signedGrant,
	action *signedAction,
	context *verifierContext,
) error {
	parent := anchor.budget
	for _, grant := range chain {
		child := grant.budget
		if parent != nil {
			if child == nil {
				return denied("delegation-expanded")
			}
			if err := requireBudgetAlgebra(parent, context); err != nil {
				return err
			}
			if child.algebra != parent.algebra {
				return denied("local-policy-denied")
			}
			if child.value > parent.value {
				return denied("delegation-expanded")
			}
		}
		parent = child
	}
	if parent == nil {
		return nil
	}
	if action.budget == nil {
		if profileContains(context.budgetFreeProfiles, action.profile) {
			return nil
		}
		return denied("budget-ceiling-exceeded")
	}
	if err := requireBudgetAlgebra(parent, context); err != nil {
		return err
	}
	if action.budget.algebra != parent.algebra {
		return denied("local-policy-denied")
	}
	if action.budget.value > parent.value {
		return denied("budget-ceiling-exceeded")
	}
	return nil
}

func uriNamespaceMatches(namespace, resource string) bool {
	if resource == namespace {
		return true
	}
	if !strings.HasPrefix(resource, namespace) {
		return false
	}
	suffix := strings.TrimPrefix(resource, namespace)
	return strings.HasSuffix(namespace, "/") ||
		strings.HasPrefix(suffix, "/") ||
		strings.HasPrefix(suffix, "?") ||
		strings.HasPrefix(suffix, "#")
}

type effectiveAuthority struct {
	subject         string
	allowedProfiles []profile
	selectedProfile *profile
	permissions     []permission
	notBefore       uint64
	expiresAt       uint64
	audiences       []string
	constraint      constraint
	budget          *budget
	remainingDepth  uint64
	lastGrant       []byte
	assurance       string
	status          statusPolicy
	extensions      []criticalExtension
	extensionsSet   bool
}

// delegate applies one grant edge. accepted lists the critical-extension
// identifiers the verifier context accepts; only those have a law.
func (authority *effectiveAuthority) delegate(grant *signedGrant, accepted []string) error {
	if grant.issuer != authority.subject || !bytes.Equal(grant.parent, authority.lastGrant) {
		return denied("broken-grant-chain")
	}
	profileAllowed := authority.selectedProfile == nil &&
		profileContains(authority.allowedProfiles, grant.profile)
	if authority.selectedProfile != nil {
		profileAllowed = equalProfile(*authority.selectedProfile, grant.profile)
	}
	if authority.remainingDepth == 0 || grant.remainingDepth >= authority.remainingDepth ||
		!profileAllowed || !permissionSubset(grant.perms, authority.permissions) ||
		grant.notBefore < authority.notBefore || grant.expiresAt > authority.expiresAt ||
		!stringSetSubset(grant.audiences, authority.audiences) ||
		!constraintAttenuates(grant.constraint, authority.constraint) ||
		!budgetAttenuates(grant.budget, authority.budget) ||
		!statusAttenuates(grant.status, authority.status) ||
		grant.assurance != authority.assurance ||
		(authority.extensionsSet &&
			!extensionsAttenuate(grant.extensions, authority.extensions, accepted)) {
		return denied("delegation-expanded")
	}
	authority.subject = grant.subject
	selected := grant.profile
	authority.selectedProfile = &selected
	authority.permissions = grant.perms
	authority.notBefore = grant.notBefore
	authority.expiresAt = grant.expiresAt
	authority.audiences = grant.audiences
	authority.constraint = grant.constraint
	authority.budget = grant.budget
	authority.remainingDepth = grant.remainingDepth
	authority.lastGrant = grant.id
	authority.status = grant.status
	authority.extensions = grant.extensions
	authority.extensionsSet = true
	return nil
}

func (authority *effectiveAuthority) authorizes(action *signedAction, budgetFree bool) error {
	if action.actor != authority.subject || !bytes.Equal(action.terminalGrant, authority.lastGrant) {
		return denied("broken-grant-chain")
	}
	profileAllowed := authority.selectedProfile == nil &&
		profileContains(authority.allowedProfiles, action.profile)
	if authority.selectedProfile != nil {
		profileAllowed = equalProfile(*authority.selectedProfile, action.profile)
	}
	if !profileAllowed {
		return denied("broken-grant-chain")
	}
	if !permissionSubset([]permission{action.permission}, authority.permissions) {
		return denied("permission-not-granted")
	}
	if action.notBefore < authority.notBefore || action.expiresAt > authority.expiresAt {
		return denied("action-outside-validity")
	}
	if !containsText(authority.audiences, action.audience) {
		return denied("audience-mismatch")
	}
	if !constraintAllows(authority.constraint, action.bodyDigest) {
		return denied("action-constraint-mismatch")
	}
	if !budgetCovers(authority.budget, action.budget, budgetFree) {
		return denied("budget-ceiling-exceeded")
	}
	return nil
}

func report(control verifiedControl, role uint64) participantReport {
	return participantReport{
		principal: control.principal, role: role,
		claims: control.claims, adapter: control.adapter,
	}
}

func assuranceSatisfied(
	requirements []assuranceRequirement,
	reports []participantReport,
	evaluationTime uint64,
) bool {
	for _, requirement := range requirements {
		selected := 0
		satisfied := 0
		for _, report := range reports {
			if report.role != requirement.role {
				continue
			}
			selected++
			reportSatisfied := false
			for _, claim := range report.claims {
				if claim.kind != requirement.claim {
					continue
				}
				if requirement.maximumAge == nil {
					reportSatisfied = true
				} else if claim.observedAt != nil &&
					*claim.observedAt <= evaluationTime &&
					evaluationTime-*claim.observedAt <= *requirement.maximumAge {
					reportSatisfied = true
				}
			}
			if reportSatisfied {
				satisfied++
			} else if requirement.quantifier == 1 {
				return false
			}
		}
		if selected == 0 || satisfied == 0 ||
			(requirement.quantifier == 1 && satisfied != selected) {
			return false
		}
	}
	return true
}

// statusListing says what an absent status statement means for a subject.
type statusListing int

const (
	// statusRequired: the snapshot must name the subject.
	statusRequired statusListing = iota
	// statusRevocationList: a subject the snapshot does not name is active.
	statusRevocationList
)

// statusEntry is the part of a principal- or grant-status statement that
// selection reads.
type statusEntry struct {
	method     string
	issuer     string
	state      uint64
	sequence   uint64
	observedAt uint64
	validUntil uint64
}

// evaluateStatusExtensions applies the accepted-extension rule to one status
// statement about a principal or grant being evaluated. No registered critical
// extension defines status semantics, and a grant or action handler never
// evaluates a status statement, so the first extension decides: one the
// context does not accept is unknown, and an accepted one has no status
// handler.
func evaluateStatusExtensions(extensions []criticalExtension, accepted []string) error {
	if len(extensions) == 0 {
		return nil
	}
	if !containsText(accepted, extensions[0].id) {
		return denied("critical-extension-unknown")
	}
	return indeterminate("unsupported-critical-extension")
}

func statusControl(controls map[string]verifiedControl, kind uint64, id []byte) error {
	control, ok := controls[statementReference{kind: kind, id: id}.key()]
	if !ok {
		return indeterminate("missing-principal-evidence")
	}
	return control.err
}

// outOfScope reports whether a snapshot statement by issuer takes no part in a
// branch evaluated under anchor: a rule of the snapshot names the issuer, and
// the issuer's scope does not cover the anchor. The decoder guarantees every
// rule naming one issuer carries the same scope, so the first one decides. A
// statement whose issuer no rule names is never out of scope.
func outOfScope(trust []statusTrustRule, issuer string, anchor *trustAnchor) bool {
	for _, rule := range trust {
		if rule.issuer == issuer {
			return !rule.scope.covers(anchor, issuer)
		}
	}
	return false
}

// selectStatus follows the exact status method over the in-scope statements
// about one subject: a trusted statement below its issuer's sequence floor is
// a rollback, and freshness and state are judged across every trusted
// statement at the greatest sequence. Its candidates are already filtered by
// scope, so it needs no anchor.
func selectStatus(
	candidates []statusEntry,
	policy statusPolicy,
	trust []statusTrustRule,
	evaluationTime uint64,
	revoked string,
) error {
	methodMatch := false
	for _, candidate := range candidates {
		if candidate.method == policy.method {
			methodMatch = true
		}
	}
	if !methodMatch {
		return denied("status-method-mismatch")
	}
	trusted := make([]statusEntry, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.method != policy.method {
			continue
		}
		var rule *statusTrustRule
		for index := range trust {
			if trust[index].method == policy.method && trust[index].issuer == candidate.issuer {
				rule = &trust[index]
				break
			}
		}
		if rule == nil {
			continue
		}
		if candidate.sequence < rule.minimumSequence {
			return denied("status-sequence-rollback")
		}
		trusted = append(trusted, candidate)
	}
	if len(trusted) == 0 {
		return denied("status-issuer-untrusted")
	}
	maximum := trusted[0].sequence
	for _, candidate := range trusted[1:] {
		if candidate.sequence > maximum {
			maximum = candidate.sequence
		}
	}
	for _, candidate := range trusted {
		if candidate.sequence == maximum &&
			(candidate.observedAt > evaluationTime || candidate.validUntil < evaluationTime ||
				evaluationTime-candidate.observedAt > policy.maxAge) {
			return indeterminate("stale-status")
		}
	}
	for _, candidate := range trusted {
		if candidate.sequence == maximum && candidate.state != 0 {
			return denied(revoked)
		}
	}
	return nil
}

// checkPrincipalStatus evaluates one principal of a branch evaluated under
// anchor. A statement out of scope for the anchor is skipped before every
// step, so the result is the one the snapshot would give without it.
func checkPrincipalStatus(
	policy statusPolicy,
	principal string,
	listing statusListing,
	anchor *trustAnchor,
	context *verifierContext,
	controls map[string]verifiedControl,
) error {
	return principalStatusIn(
		policy, principal, listing,
		func(issuer string) bool { return outOfScope(context.principalSnapshot.trust, issuer, anchor) },
		context, controls,
	)
}

// principalStatusIn evaluates one principal against the principal-status
// snapshot, where a statement whose issuer excluded reports takes no part in
// any step.
func principalStatusIn(
	policy statusPolicy,
	principal string,
	listing statusListing,
	excluded func(issuer string) bool,
	context *verifierContext,
	controls map[string]verifiedControl,
) error {
	if policy.kind == 0 {
		return nil
	}
	if !containsText(context.principalStatuses, policy.method) {
		return indeterminate("unsupported-status-method")
	}
	snapshot := context.principalSnapshot
	candidates := make([]statusEntry, 0)
	for _, statement := range snapshot.statements {
		if statement.principal != principal || excluded(statement.issuer) {
			continue
		}
		if err := statusControl(controls, 2, statement.id); err != nil {
			return err
		}
		if err := evaluateStatusExtensions(statement.extensions, context.extensions); err != nil {
			return err
		}
		candidates = append(candidates, statusEntry{
			method: statement.method, issuer: statement.issuer, state: statement.state,
			sequence: statement.sequence, observedAt: statement.observedAt,
			validUntil: statement.validUntil,
		})
	}
	if snapshot.observedAt > context.evaluationTime || snapshot.validUntil < context.evaluationTime {
		return indeterminate("stale-status")
	}
	if len(candidates) == 0 {
		if listing == statusRevocationList {
			return nil
		}
		return indeterminate("missing-principal-status")
	}
	return selectStatus(candidates, policy, snapshot.trust, context.evaluationTime, "principal-revoked")
}

// checkGrantStatus evaluates one grant of a branch evaluated under anchor,
// skipping out-of-scope statements as checkPrincipalStatus does.
func checkGrantStatus(
	policy statusPolicy,
	grantID []byte,
	anchor *trustAnchor,
	context *verifierContext,
	controls map[string]verifiedControl,
) error {
	if policy.kind == 0 {
		return nil
	}
	if !containsText(context.grantStatuses, policy.method) {
		return indeterminate("unsupported-status-method")
	}
	snapshot := context.grantSnapshot
	candidates := make([]statusEntry, 0)
	for _, statement := range snapshot.statements {
		if !bytes.Equal(statement.grantID, grantID) ||
			outOfScope(snapshot.trust, statement.issuer, anchor) {
			continue
		}
		if err := statusControl(controls, 3, statement.id); err != nil {
			return err
		}
		if err := evaluateStatusExtensions(statement.extensions, context.extensions); err != nil {
			return err
		}
		candidates = append(candidates, statusEntry{
			method: statement.method, issuer: statement.issuer, state: statement.state,
			sequence: statement.sequence, observedAt: statement.observedAt,
			validUntil: statement.validUntil,
		})
	}
	if snapshot.observedAt > context.evaluationTime || snapshot.validUntil < context.evaluationTime {
		return indeterminate("stale-status")
	}
	if len(candidates) == 0 {
		return indeterminate("missing-grant-status")
	}
	return selectStatus(candidates, policy, snapshot.trust, context.evaluationTime, "grant-revoked")
}

func uniqueDigests(values [][]byte) [][]byte {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if !bytes.Equal(value, result[len(result)-1]) {
			result = append(result, value)
		}
	}
	return result
}

func uniqueReports(values []participantReport) []participantReport {
	result := make([]participantReport, 0, len(values))
	for _, value := range values {
		duplicate := false
		for _, candidate := range result {
			if value.principal == candidate.principal && value.role == candidate.role &&
				value.adapter == candidate.adapter && claimsEqual(value.claims, candidate.claims) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			result = append(result, value)
		}
	}
	return result
}

func claimsEqual(left, right []assuranceClaim) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].kind != right[index].kind {
			return false
		}
		if left[index].observedAt == nil || right[index].observedAt == nil {
			if left[index].observedAt != nil || right[index].observedAt != nil {
				return false
			}
		} else if *left[index].observedAt != *right[index].observedAt {
			return false
		}
	}
	return true
}
