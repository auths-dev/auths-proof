package auths

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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

type semanticResult struct {
	name      string
	decision  string
	code      string
	proof     []byte
	context   []byte
	action    []byte
	plan      []byte
	actionIDs [][]byte
	branches  [][]byte
	assurance []participantReport
}

func semanticAudit(input manifest, root string) (string, error) {
	summary := sha256.New()
	for _, fixture := range input.Fixtures {
		proofBytes, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(fixture.Proof.Path)))
		if err != nil {
			return "", err
		}
		contextBytes, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(fixture.Context.Path)))
		if err != nil {
			return "", err
		}
		actionArtifact, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(fixture.CanonicalAction.Path)))
		if err != nil {
			return "", err
		}
		actionBytes, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(fixture.CanonicalBody.Path)))
		if err != nil {
			return "", err
		}
		action, err := decodeCanonicalAction(actionArtifact)
		if err != nil {
			return "", err
		}
		if !bytes.Equal(action.body, actionBytes) {
			return "", fmt.Errorf("%s canonical action/body mismatch", fixture.Name)
		}
		result := verifySemantic(
			fixture.Name, proofBytes, contextBytes, actionArtifact, *action, input.AdapterContext,
		)
		if result.decision != fixtureExpectedDecision(fixture) || result.code != fixture.ExpectedCode {
			return "", fmt.Errorf(
				"%s independently derived %s/%s, manifest requires %s/%s",
				fixture.Name,
				result.decision,
				result.code,
				fixtureExpectedDecision(fixture),
				fixture.ExpectedCode,
			)
		}
		writeSemanticResult(summary, result)
	}
	return fmt.Sprintf("%d:%x", len(input.Fixtures), summary.Sum(nil)), nil
}

func decodeCanonicalAction(data []byte) (*canonicalAction, error) {
	root, err := decodeValue(data)
	if err != nil {
		return nil, err
	}
	if err := exactMap(root, 6); err != nil {
		return nil, err
	}
	actionProfile, err := profileValue(mustMap(root, 0))
	if err != nil {
		return nil, err
	}
	mediaType, err := textValue(mustMap(root, 1))
	if err != nil {
		return nil, err
	}
	body, err := bytesValue(mustMap(root, 2), -1)
	if err != nil {
		return nil, err
	}
	actionPermission, err := permissionValue(mustMap(root, 3))
	if err != nil {
		return nil, err
	}
	actionBudget, err := budgetValue(mustMap(root, 4))
	if err != nil {
		return nil, err
	}
	detachedNodes, err := arrayValue(mustMap(root, 5))
	if err != nil {
		return nil, err
	}
	detached := make([]detachedAttachment, 0, len(detachedNodes))
	for _, node := range detachedNodes {
		if err := exactMap(node, 2); err != nil {
			return nil, err
		}
		digest, err := bytesValue(mustMap(node, 0), 32)
		if err != nil {
			return nil, err
		}
		attachmentBytes, err := bytesValue(mustMap(node, 1), -1)
		if err != nil {
			return nil, err
		}
		detached = append(detached, detachedAttachment{digest: digest, bytes: attachmentBytes})
	}
	return &canonicalAction{
		body: body, profile: actionProfile, mediaType: mediaType,
		permission: actionPermission, budget: actionBudget, detached: detached,
	}, nil
}

func fixtureExpectedDecision(value fixture) string {
	// ExpectedDecision is added to the manifest model below; retaining this
	// helper makes the comparison explicit and keeps expected data out of the
	// verifier itself.
	return value.ExpectedDecision
}

func writeSemanticResult(summary interface{ Write([]byte) (int, error) }, result semanticResult) {
	writeField := func(value string) {
		summary.Write([]byte(value))
		summary.Write([]byte{0})
	}
	writeBytes := func(value []byte) {
		writeField(hex.EncodeToString(value))
	}
	writeField(result.name)
	writeField(result.decision)
	writeField(result.code)
	writeBytes(result.proof)
	writeBytes(result.context)
	writeBytes(result.action)
	writeBytes(result.plan)
	for _, id := range result.actionIDs {
		writeBytes(id)
	}
	writeField("|")
	for _, branch := range result.branches {
		writeBytes(branch)
	}
	writeField("|")
	for _, report := range result.assurance {
		writeField(report.principal)
		writeField(fmt.Sprintf("%d", report.role))
		writeField(report.adapter)
		claims := append([]assuranceClaim(nil), report.claims...)
		sort.Slice(claims, func(i, j int) bool {
			if claims[i].kind != claims[j].kind {
				return claims[i].kind < claims[j].kind
			}
			if claims[i].observedAt == nil || claims[j].observedAt == nil {
				return claims[i].observedAt == nil && claims[j].observedAt != nil
			}
			return *claims[i].observedAt < *claims[j].observedAt
		})
		for _, claim := range claims {
			writeField(claim.kind)
			if claim.observedAt == nil {
				writeField("-")
			} else {
				writeField(fmt.Sprintf("%d", *claim.observedAt))
			}
		}
		writeField(";")
	}
	writeField("\n")
}

func verifySemantic(
	name string,
	proofBytes []byte,
	contextBytes []byte,
	actionBytes []byte,
	action canonicalAction,
	adapters adapterContext,
) semanticResult {
	result := semanticResult{
		name:    name,
		proof:   sha256Bytes(proofBytes),
		action:  sha256Bytes(actionBytes),
		context: domainHash(9, contextBytes),
	}
	context, err := decodeContext(contextBytes)
	if err != nil {
		result.decision, result.code = "denied", "malformed-proof"
		return result
	}
	bundle, err := decodeBundle(proofBytes, context.limits)
	if err != nil {
		return failedResult(result, err)
	}
	result.plan = domainHash(3, bundle.plan.raw)
	if context.composition.expectedPlan != nil &&
		!bytes.Equal(context.composition.expectedPlan, result.plan) {
		return failedResult(result, denied("composition-requirement-not-met"))
	}
	controls, err := resolveAndVerifyControl(bundle, context, adapters)
	if err != nil {
		return failedResult(result, err)
	}
	actionIDs, branches, assurance, err := verifyAuthority(bundle, controls, context, action)
	if err != nil {
		return failedResult(result, err)
	}
	result.decision = "authorized"
	result.code = "authorized"
	result.actionIDs = actionIDs
	result.branches = branches
	result.assurance = assurance
	return result
}

func failedResult(result semanticResult, err error) semanticResult {
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

func resolveAndVerifyControl(
	bundle *proofBundle,
	context *verifierContext,
	adapters adapterContext,
) ([]verifiedControl, error) {
	if !bytes.Equal(context.registryManifest, bytes.Repeat([]byte{0x33}, 32)) {
		return nil, denied("registry-manifest-mismatch")
	}
	localConfiguration, err := hex.DecodeString(adapters.Configuration)
	if err != nil || len(localConfiguration) != 32 ||
		!bytes.Equal(context.configuration, localConfiguration) {
		return nil, denied("verifier-configuration-mismatch")
	}
	planID := domainHash(3, bundle.plan.raw)
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

func validateCarriedStatus(bundle *proofBundle, context *verifierContext) error {
	for _, carried := range bundle.principalStatus {
		for _, current := range context.principalSnapshot.statements {
			if carried.principal == current.principal &&
				carried.purpose == current.purpose &&
				current.sequence > carried.sequence {
				return denied("status-sequence-rollback")
			}
		}
		found := false
		for _, current := range context.principalSnapshot.statements {
			if bytes.Equal(carried.statement.raw, current.statement.raw) &&
				bytes.Equal(carried.signature.signature, current.signature.signature) {
				found = true
			}
		}
		if !found {
			return denied("digest-mismatch")
		}
	}
	for _, carried := range bundle.grantStatus {
		for _, current := range context.grantSnapshot.statements {
			if bytes.Equal(carried.grantID, current.grantID) && current.sequence > carried.sequence {
				return denied("status-sequence-rollback")
			}
		}
		found := false
		for _, current := range context.grantSnapshot.statements {
			if bytes.Equal(carried.statement.raw, current.statement.raw) &&
				bytes.Equal(carried.signature.signature, current.signature.signature) {
				found = true
			}
		}
		if !found {
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
) ([][]byte, [][]byte, []participantReport, error) {
	if !containsText(context.resourceMatchers, context.resourceMatcher) ||
		context.resourceMatcher != "uri-namespace-v1" {
		return nil, nil, nil, indeterminate("unsupported-resource-matcher")
	}
	if !containsText(context.profilePolicies, context.profilePolicy) ||
		context.profilePolicy != "exact-v1" {
		return nil, nil, nil, indeterminate("unsupported-profile-policy")
	}
	for _, anchor := range context.anchors {
		if err := requireBudgetAlgebra(anchor.budget, context); err != nil {
			return nil, nil, nil, err
		}
	}
	for _, grant := range bundle.grants {
		if err := requireBudgetAlgebra(grant.budget, context); err != nil {
			return nil, nil, nil, err
		}
	}
	for _, action := range bundle.actions {
		if err := requireBudgetAlgebra(action.budget, context); err != nil {
			return nil, nil, nil, err
		}
	}
	if err := validateAttachments(bundle, canonical, context); err != nil {
		return nil, nil, nil, err
	}
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

func evaluateCriticalExtensions(extensions []criticalExtension, accepted []string) error {
	for _, extension := range extensions {
		if !containsText(accepted, extension.id) {
			return denied("critical-extension-unknown")
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
	resourceAllowed := false
	for _, namespace := range anchor.namespaces {
		if uriNamespaceMatches(namespace, action.permission.resource) {
			resourceAllowed = true
		}
	}
	if !resourceAllowed {
		return nil, denied("resource-namespace-mismatch")
	}
	principalStatusValue, err := checkPrincipalStatus(anchor.status, anchor.principal, context)
	if err != nil {
		return nil, err
	}
	if principalStatusValue != nil {
		control, ok := controls[statementReference{kind: 2, id: principalStatusValue.id}.key()]
		if !ok {
			return nil, indeterminate("missing-principal-evidence")
		}
		if control.err != nil {
			return nil, control.err
		}
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
		grantStatusValue, err := checkGrantStatus(grant.status, grant.id, context)
		if err != nil {
			return nil, err
		}
		if grantStatusValue != nil {
			control, ok := controls[statementReference{kind: 3, id: grantStatusValue.id}.key()]
			if !ok {
				return nil, indeterminate("missing-principal-evidence")
			}
			if control.err != nil {
				return nil, control.err
			}
		}
		if err := authority.delegate(grant); err != nil {
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

func (authority *effectiveAuthority) delegate(grant *signedGrant) error {
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
		(authority.extensionsSet && !extensionSliceEqual(grant.extensions, authority.extensions)) {
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

func trustedStatus(
	trust []statusTrustRule,
	method string,
	issuer string,
	sequence uint64,
) bool {
	for _, rule := range trust {
		if rule.method == method && rule.issuer == issuer && sequence >= rule.minimumSequence {
			return true
		}
	}
	return false
}

func checkPrincipalStatus(
	policy statusPolicy,
	principal string,
	context *verifierContext,
) (*principalStatus, error) {
	if policy.kind == 0 {
		return nil, nil
	}
	if !containsText(context.principalStatuses, policy.method) {
		return nil, indeterminate("unsupported-status-method")
	}
	snapshot := context.principalSnapshot
	if snapshot.observedAt > context.evaluationTime || snapshot.validUntil < context.evaluationTime {
		return nil, indeterminate("stale-status")
	}
	var selected *principalStatus
	methodMatch := false
	for _, statement := range snapshot.statements {
		if statement.principal == principal && statement.method == policy.method {
			methodMatch = true
			if trustedStatus(snapshot.trust, statement.method, statement.issuer, statement.sequence) &&
				(selected == nil || statement.sequence > selected.sequence ||
					(statement.sequence == selected.sequence && statement.state > selected.state)) {
				selected = statement
			}
		}
	}
	if selected != nil {
		if selected.observedAt > context.evaluationTime ||
			context.evaluationTime-selected.observedAt > policy.maxAge {
			return nil, indeterminate("stale-status")
		}
		if selected.state != 0 {
			return nil, denied("principal-revoked")
		}
		return selected, nil
	}
	if methodMatch {
		return nil, denied("status-issuer-untrusted")
	}
	for _, statement := range snapshot.statements {
		if statement.principal == principal {
			return nil, denied("status-method-mismatch")
		}
	}
	return nil, indeterminate("missing-principal-status")
}

func checkGrantStatus(
	policy statusPolicy,
	grantID []byte,
	context *verifierContext,
) (*grantStatus, error) {
	if policy.kind == 0 {
		return nil, nil
	}
	if !containsText(context.grantStatuses, policy.method) {
		return nil, indeterminate("unsupported-status-method")
	}
	snapshot := context.grantSnapshot
	if snapshot.observedAt > context.evaluationTime || snapshot.validUntil < context.evaluationTime {
		return nil, indeterminate("stale-status")
	}
	var selected *grantStatus
	methodMatch := false
	for _, statement := range snapshot.statements {
		if bytes.Equal(statement.grantID, grantID) && statement.method == policy.method {
			methodMatch = true
			if trustedStatus(snapshot.trust, statement.method, statement.issuer, statement.sequence) &&
				(selected == nil || statement.sequence > selected.sequence ||
					(statement.sequence == selected.sequence && statement.state > selected.state)) {
				selected = statement
			}
		}
	}
	if selected != nil {
		if selected.observedAt > context.evaluationTime ||
			context.evaluationTime-selected.observedAt > policy.maxAge {
			return nil, indeterminate("stale-status")
		}
		if selected.state != 0 {
			return nil, denied("grant-revoked")
		}
		return selected, nil
	}
	if methodMatch {
		return nil, denied("status-issuer-untrusted")
	}
	for _, statement := range snapshot.statements {
		if bytes.Equal(statement.grantID, grantID) {
			return nil, denied("status-method-mismatch")
		}
	}
	return nil, indeterminate("missing-grant-status")
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
