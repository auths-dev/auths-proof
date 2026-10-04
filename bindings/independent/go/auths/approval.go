package auths

// Independent native K-of-N approvals: approver anchors and approval
// requirements in the trusted context, the approval-requirement-v1 grant
// extension, signed approvals carried by the proof, and the evaluation that
// counts distinct approvers. Written from the V1 specification, not from the
// Rust verifier.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"sort"
)

// verifierLimits holds the thirty deployment limits of the trusted context,
// indexed by their verifier-limits key.
type verifierLimits = [30]uint64

// hardLimits are the protocol hard maxima of the verifier-limits keys. A
// context whose deployment limit exceeds its hard maximum does not decode.
var hardLimits = verifierLimits{
	8388608, 16777216, 16777216, 256, 128, 128, 16, 128, 512, 2097152,
	512, 512, 512, 512, 8388608, 1024, 4096, 1024, 256, 32,
	65536, 256, 32, 8388608, 1024, 1024, 1000000, 128, 32, 4,
}

const (
	approvalExtension           = "approval-requirement-v1"
	approvalObjectKind          = 10
	approvalRequirementIDKind   = 12
	approvalPurposeAssertion    = 2
	maxApprovalBytes            = 4096
	maxApprovalEvidence         = 4
	maxApproversPerRequirement  = 16
	maxRequirementsPerExtension = 4
	maxApprovalRequirementChain = 16
	maxApprovalEvaluations      = 64
	maxApproverMethods          = 1024
	maxPrincipalIDBytes         = 512
	maxMediaTypeBytes           = 128
	maxCapabilityBytes          = 128
	maxResourceBytes            = 1024
	maxAudienceBytes            = 512
)

// errApprovalLimit marks approval-requirement bytes above a structural bound:
// more than four requirements in one extension or more than sixteen
// approvers in one requirement.
var errApprovalLimit = errors.New("approval-requirement limit exceeded")

// errContextLimit marks a trusted context with more approver anchors or
// approval requirements than its limits, or more than sixteen approvers in
// one requirement. It is resource-limit-exceeded at context decode, where
// every other context decode failure is malformed-proof.
var errContextLimit = errors.New("trusted-context approval limit exceeded")

// approverAnchor lets the verifier check one approver's signatures and
// nothing else. It is no trust anchor and no observer anchor.
type approverAnchor struct {
	principal string
	methods   []string
	notBefore uint64
	expiresAt uint64
	status    statusPolicy
}

// approvalRequirement is "K of these approvers", identified by the domain
// hash of its canonical bytes.
type approvalRequirement struct {
	id        []byte
	approvers []string
	k         uint64
}

// signedApproval is one decoded proof-carried approval. digest is the raw
// SHA-256 of its exact canonical bytes.
type signedApproval struct {
	raw          []byte
	digest       []byte
	approver     string
	requirement  []byte
	mediaType    string
	bodyDigest   []byte
	permission   permission
	budget       *budget
	attributes   []byte
	audience     string
	challenge    []byte
	notBefore    uint64
	expiresAt    uint64
	statementRaw []byte
	signature    signatureEnvelope
	evidence     []*evidenceObject
}

// boundedText reads a text string of minimum to maximum UTF-8 bytes.
func boundedText(value *cborValue, minimum, maximum int) (string, error) {
	text, err := textValue(value)
	if err != nil || len(text) < minimum || len(text) > maximum {
		return "", errors.New("text outside its bounds")
	}
	return text, nil
}

// ascendingTexts reads a definite array of minimum to maximum text strings,
// each of 1 to itemMaximum bytes and strictly ascending in UTF-8 byte order.
// A longer array is errApprovalLimit when limitCount is set, and invalid
// otherwise.
func ascendingTexts(value *cborValue, minimum, maximum, itemMaximum int, limitCount bool) ([]string, error) {
	nodes, err := arrayValue(value)
	if err != nil {
		return nil, err
	}
	if len(nodes) > maximum {
		if limitCount {
			return nil, errApprovalLimit
		}
		return nil, errors.New("too many entries")
	}
	if len(nodes) < minimum {
		return nil, errors.New("too few entries")
	}
	result := make([]string, 0, len(nodes))
	for _, node := range nodes {
		text, err := boundedText(node, 1, itemMaximum)
		if err != nil {
			return nil, err
		}
		if len(result) > 0 && result[len(result)-1] >= text {
			return nil, errors.New("entries are not strictly ascending")
		}
		result = append(result, text)
	}
	return result, nil
}

// decodeApprovalRequirement reads one canonical approval requirement: one to
// sixteen approver principals, strictly ascending, and a threshold K between
// one and their number. More than sixteen approvers is errApprovalLimit.
func decodeApprovalRequirement(value *cborValue) (approvalRequirement, error) {
	if err := exactMap(value, 2); err != nil {
		return approvalRequirement{}, err
	}
	approvers, err := ascendingTexts(
		mustMap(value, 0), 1, maxApproversPerRequirement, maxPrincipalIDBytes, true,
	)
	if err != nil {
		return approvalRequirement{}, err
	}
	k, err := uintValue(mustMap(value, 1))
	if err != nil || k == 0 || k > maxApproversPerRequirement || k > uint64(len(approvers)) {
		return approvalRequirement{}, errors.New("invalid approval threshold")
	}
	return approvalRequirement{
		id:        domainHash(approvalRequirementIDKind, value.raw),
		approvers: approvers,
		k:         k,
	}, nil
}

// decodeApprovalRequirements reads the exact bytes of an
// approval-requirement-v1 extension: one to four requirements, strictly
// ascending by identifier. Bytes above a bound are errApprovalLimit; any
// other invalid or non-canonical bytes are another error.
func decodeApprovalRequirements(data []byte) ([]approvalRequirement, error) {
	root, err := decodeValue(data)
	if err != nil {
		return nil, err
	}
	nodes, err := arrayValue(root)
	if err != nil {
		return nil, err
	}
	if len(nodes) > maxRequirementsPerExtension {
		return nil, errApprovalLimit
	}
	if len(nodes) == 0 {
		return nil, errors.New("empty approval requirements")
	}
	requirements := make([]approvalRequirement, 0, len(nodes))
	for _, node := range nodes {
		requirement, err := decodeApprovalRequirement(node)
		if err != nil {
			return nil, err
		}
		if len(requirements) > 0 &&
			bytes.Compare(requirements[len(requirements)-1].id, requirement.id) >= 0 {
			return nil, errors.New("approval requirements are not strictly ascending")
		}
		requirements = append(requirements, requirement)
	}
	return requirements, nil
}

// evaluateApprovalExtension is the approval-requirement-v1 handler: a bound
// is resource-limit-exceeded and any other invalid bytes local-policy-denied.
func evaluateApprovalExtension(extension criticalExtension) error {
	if _, err := decodeApprovalRequirements(extension.bytes); err != nil {
		if errors.Is(err, errApprovalLimit) {
			return denied("resource-limit-exceeded")
		}
		return denied("local-policy-denied")
	}
	return nil
}

// approvalRequirementCovers reports whether child narrows parent: the child's
// approvers are a subset of the parent's and its K is no lower.
func approvalRequirementCovers(child, parent approvalRequirement) bool {
	return child.k >= parent.k && stringSetSubset(child.approvers, parent.approvers)
}

// approvalRequirementsAttenuate is the extension's attenuation law: every
// parent requirement is covered by some child requirement. The child may add
// requirements.
func approvalRequirementsAttenuate(child, parent []approvalRequirement) bool {
	for _, required := range parent {
		covered := false
		for _, candidate := range child {
			covered = covered || approvalRequirementCovers(candidate, required)
		}
		if !covered {
			return false
		}
	}
	return true
}

// approvalLaw applies the attenuation law to one edge; a nil parent is a
// parent without the extension, which any valid child narrows.
func approvalLaw(child, parent *criticalExtension) bool {
	childRequirements, err := decodeApprovalRequirements(child.bytes)
	if err != nil {
		return false
	}
	if parent == nil {
		return true
	}
	parentRequirements, err := decodeApprovalRequirements(parent.bytes)
	if err != nil {
		return false
	}
	return approvalRequirementsAttenuate(childRequirements, parentRequirements)
}

// decodeApproverAnchors reads context key 15: at most the approver-anchor
// limit of anchors, strictly ascending by principal. More anchors than the
// limit is errContextLimit.
func decodeApproverAnchors(value *cborValue, limit uint64) ([]*approverAnchor, error) {
	nodes, err := arrayValue(value)
	if err != nil {
		return nil, err
	}
	if uint64(len(nodes)) > limit {
		return nil, errContextLimit
	}
	anchors := make([]*approverAnchor, 0, len(nodes))
	for _, node := range nodes {
		if err := exactMap(node, 5); err != nil {
			return nil, err
		}
		anchor := &approverAnchor{}
		if anchor.principal, err = boundedText(mustMap(node, 0), 1, maxPrincipalIDBytes); err != nil {
			return nil, err
		}
		if anchor.methods, err = ascendingTexts(
			mustMap(node, 1), 1, maxApproverMethods, maxBoundedIDBytes, false,
		); err != nil {
			return nil, err
		}
		if anchor.notBefore, err = uintValue(mustMap(node, 2)); err != nil {
			return nil, err
		}
		if anchor.expiresAt, err = uintValue(mustMap(node, 3)); err != nil {
			return nil, err
		}
		if anchor.notBefore > anchor.expiresAt {
			return nil, errors.New("invalid approver-anchor validity")
		}
		if anchor.status, err = statusPolicyValue(mustMap(node, 4)); err != nil {
			return nil, err
		}
		if len(anchors) > 0 && anchors[len(anchors)-1].principal >= anchor.principal {
			return nil, errors.New("approver anchors are not strictly ascending by principal")
		}
		anchors = append(anchors, anchor)
	}
	return anchors, nil
}

// decodeContextRequirements reads context key 16: at most the requirement
// limit of requirements, strictly ascending by identifier, so none repeats.
// More requirements than the limit, or more than sixteen approvers in one,
// is errContextLimit.
func decodeContextRequirements(value *cborValue, limit uint64) ([]approvalRequirement, error) {
	nodes, err := arrayValue(value)
	if err != nil {
		return nil, err
	}
	if uint64(len(nodes)) > limit {
		return nil, errContextLimit
	}
	requirements := make([]approvalRequirement, 0, len(nodes))
	for _, node := range nodes {
		requirement, err := decodeApprovalRequirement(node)
		if errors.Is(err, errApprovalLimit) {
			return nil, errContextLimit
		}
		if err != nil {
			return nil, err
		}
		if len(requirements) > 0 &&
			bytes.Compare(requirements[len(requirements)-1].id, requirement.id) >= 0 {
			return nil, errors.New("context approval requirements are not strictly ascending")
		}
		requirements = append(requirements, requirement)
	}
	return requirements, nil
}

// validateApprovals rejects a context whose approval configuration is
// inconsistent: an approver anchor accepting a principal method or a
// principal-status method the context does not accept, or a requirement
// naming a principal without an approver anchor.
func validateApprovals(context *verifierContext) error {
	anchored := make(map[string]bool, len(context.approverAnchors))
	for _, anchor := range context.approverAnchors {
		for _, method := range anchor.methods {
			if !containsText(context.principalMethods, method) {
				return errors.New("approver anchor accepts an unaccepted principal method")
			}
		}
		if anchor.status.kind == 1 && !containsText(context.principalStatuses, anchor.status.method) {
			return errors.New("approver anchor names an unaccepted principal-status method")
		}
		anchored[anchor.principal] = true
	}
	for _, requirement := range context.approvalRequirements {
		for _, approver := range requirement.approvers {
			if !anchored[approver] {
				return errors.New("approval requirement names an approver without an anchor")
			}
		}
	}
	return nil
}

// decodeApproval reads one proof-carried signed approval. An approval longer
// than 4096 bytes or carrying more than four evidence objects is
// resource-limit-exceeded; any other invalid shape does not decode.
func decodeApproval(value *cborValue, limits verifierLimits) (*signedApproval, error) {
	if len(value.raw) > maxApprovalBytes {
		return nil, denied("resource-limit-exceeded")
	}
	if err := exactMap(value, 3); err != nil {
		return nil, err
	}
	evidenceNodes, err := arrayValue(mustMap(value, 2))
	if err != nil {
		return nil, err
	}
	if len(evidenceNodes) > maxApprovalEvidence {
		return nil, denied("resource-limit-exceeded")
	}
	statement := mustMap(value, 0)
	if err := exactMap(statement, 13); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(value.raw)
	result := &signedApproval{
		raw:          value.raw,
		digest:       digest[:],
		statementRaw: statement.raw,
	}
	if version, err := uintValue(mustMap(statement, 0)); err != nil || version != 1 {
		return nil, errors.New("unsupported approval protocol")
	}
	if result.approver, err = boundedText(mustMap(statement, 1), 1, maxPrincipalIDBytes); err != nil {
		return nil, err
	}
	if result.requirement, err = bytesValue(mustMap(statement, 2), 32); err != nil {
		return nil, err
	}
	if result.mediaType, err = boundedText(mustMap(statement, 3), 1, maxMediaTypeBytes); err != nil {
		return nil, err
	}
	if result.bodyDigest, err = bytesValue(mustMap(statement, 4), 32); err != nil {
		return nil, err
	}
	if result.permission.capability, err = boundedText(
		mustMap(statement, 5), 1, maxCapabilityBytes,
	); err != nil {
		return nil, err
	}
	if result.permission.resource, err = boundedText(
		mustMap(statement, 6), 1, maxResourceBytes,
	); err != nil {
		return nil, err
	}
	if result.budget, err = budgetValue(mustMap(statement, 7)); err != nil {
		return nil, err
	}
	if result.attributes, err = optionalBytes(mustMap(statement, 8)); err != nil {
		return nil, err
	}
	if result.audience, err = boundedText(mustMap(statement, 9), 1, maxAudienceBytes); err != nil {
		return nil, err
	}
	if result.challenge, err = bytesValue(mustMap(statement, 10), 32); err != nil {
		return nil, err
	}
	if result.notBefore, err = uintValue(mustMap(statement, 11)); err != nil {
		return nil, err
	}
	if result.expiresAt, err = uintValue(mustMap(statement, 12)); err != nil {
		return nil, err
	}
	if result.notBefore > result.expiresAt {
		return nil, errors.New("invalid approval validity")
	}
	if result.signature, err = signatureValue(mustMap(value, 1)); err != nil {
		return nil, err
	}
	for _, node := range evidenceNodes {
		object, err := decodeEvidence(node, limits[9])
		if err != nil {
			return nil, err
		}
		if len(result.evidence) > 0 &&
			bytes.Compare(result.evidence[len(result.evidence)-1].id, object.id) >= 0 {
			return nil, errors.New("approval evidence is not strictly ascending")
		}
		result.evidence = append(result.evidence, object)
	}
	return result, nil
}

// approvalVerdict is the cached outcome of one requirement: nil when it
// authorized, else approval-threshold-not-met or approval-unavailable.
type approvalVerdict struct {
	err     error
	counted [][]byte
}

// approvalEvaluator evaluates approval requirements for one verification. A
// requirement's verdict depends only on the requirement, the proof, the
// canonical action, and the context, so each distinct requirement is
// evaluated once and later appearances reuse its verdict.
type approvalEvaluator struct {
	approvals  []*signedApproval
	authority  map[string]bool
	canonical  canonicalAction
	bodyDigest []byte
	context    *verifierContext
	adapters   adapterContext
	controls   map[string]verifiedControl
	verdicts   map[string]*approvalVerdict
}

// newApprovalEvaluator removes byte-identical repeated approvals, orders the
// rest by approval digest, and fixes the authority principals: the issuer and
// subject of every grant and the actor of every action in the proof.
func newApprovalEvaluator(
	bundle *proofBundle,
	canonical canonicalAction,
	context *verifierContext,
	adapters adapterContext,
	controls map[string]verifiedControl,
) *approvalEvaluator {
	authority := make(map[string]bool)
	for _, grant := range bundle.grants {
		authority[grant.issuer] = true
		authority[grant.subject] = true
	}
	for _, action := range bundle.actions {
		authority[action.actor] = true
	}
	seen := make(map[string]bool, len(bundle.approvals))
	approvals := make([]*signedApproval, 0, len(bundle.approvals))
	for _, approval := range bundle.approvals {
		key := digestKey(approval.digest)
		if seen[key] {
			continue
		}
		seen[key] = true
		approvals = append(approvals, approval)
	}
	sort.Slice(approvals, func(left, right int) bool {
		return bytes.Compare(approvals[left].digest, approvals[right].digest) < 0
	})
	return &approvalEvaluator{
		approvals:  approvals,
		authority:  authority,
		canonical:  canonical,
		bodyDigest: sha256Bytes(canonical.body),
		context:    context,
		adapters:   adapters,
		controls:   controls,
		verdicts:   make(map[string]*approvalVerdict),
	}
}

// errApprovalEvaluations marks the 65th distinct requirement of one
// verification. Inside a branch it is that attempt's resource-limit failure;
// among the context's requirements it ends the verification.
var errApprovalEvaluations = errors.New("approval evaluations exhausted")

// evaluateList evaluates requirements in order: the first denied requirement
// stops the list with its verdict; otherwise an indeterminate requirement
// makes the list indeterminate. It returns errApprovalEvaluations when the
// verification runs out of evaluations.
func (evaluator *approvalEvaluator) evaluateList(requirements []approvalRequirement) error {
	var unavailable error
	for _, requirement := range requirements {
		verdict, err := evaluator.requirement(requirement)
		if err != nil {
			return err
		}
		var failure semanticFailure
		if errors.As(verdict.err, &failure) && failure.decision == "denied" {
			return failure
		}
		if verdict.err != nil && unavailable == nil {
			unavailable = verdict.err
		}
	}
	return unavailable
}

func (evaluator *approvalEvaluator) requirement(requirement approvalRequirement) (*approvalVerdict, error) {
	key := digestKey(requirement.id)
	if verdict := evaluator.verdicts[key]; verdict != nil {
		return verdict, nil
	}
	if len(evaluator.verdicts) >= maxApprovalEvaluations {
		return nil, errApprovalEvaluations
	}
	verdict := evaluator.evaluate(requirement)
	evaluator.verdicts[key] = verdict
	return verdict, nil
}

// approverState is one listed approver's progress through the approvals.
type approverState int

const (
	approverAbsent approverState = iota
	approverPending
	approverCounted
)

// approvalOutcome is what one approval contributes to its approver.
type approvalOutcome int

const (
	approvalSkipped approvalOutcome = iota
	approvalPending
	approvalCounted
)

// evaluate counts distinct listed approvers over the approvals in digest
// order and applies threshold_counts(K, counted, pending).
func (evaluator *approvalEvaluator) evaluate(requirement approvalRequirement) *approvalVerdict {
	states := make(map[string]approverState, len(requirement.approvers))
	for _, approver := range requirement.approvers {
		states[approver] = approverAbsent
	}
	verdict := &approvalVerdict{}
	for _, approval := range evaluator.approvals {
		state, listed := states[approval.approver]
		if !listed || evaluator.authority[approval.approver] || state == approverCounted {
			continue
		}
		switch evaluator.approval(requirement, approval) {
		case approvalCounted:
			states[approval.approver] = approverCounted
			verdict.counted = append(verdict.counted, approval.digest)
		case approvalPending:
			states[approval.approver] = approverPending
		}
	}
	var counted, pending uint64
	for _, state := range states {
		switch state {
		case approverCounted:
			counted++
		case approverPending:
			pending++
		}
	}
	switch {
	case counted >= requirement.k:
	case counted+pending >= requirement.k:
		verdict.err = indeterminate("approval-unavailable")
		verdict.counted = nil
	default:
		verdict.err = denied("approval-threshold-not-met")
		verdict.counted = nil
	}
	return verdict
}

// approval runs the per-approval checks in order: exact requirement and
// action, validity and approver anchor, the anchor's accepted method, the
// signature, and the approver's principal status.
func (evaluator *approvalEvaluator) approval(
	requirement approvalRequirement,
	approval *signedApproval,
) approvalOutcome {
	context := evaluator.context
	canonical := evaluator.canonical
	if !bytes.Equal(approval.requirement, requirement.id) ||
		approval.mediaType != canonical.mediaType ||
		!bytes.Equal(approval.bodyDigest, evaluator.bodyDigest) ||
		!equalPermission(approval.permission, canonical.permission) ||
		!equalBudget(approval.budget, canonical.budget) ||
		approval.attributes != nil ||
		approval.audience != context.expectedAudience ||
		!bytes.Equal(approval.challenge, context.expectedChallenge) {
		return approvalSkipped
	}
	now := context.evaluationTime
	if now < approval.notBefore || now > approval.expiresAt {
		return approvalSkipped
	}
	var anchor *approverAnchor
	for _, candidate := range context.approverAnchors {
		if candidate.principal == approval.approver {
			anchor = candidate
		}
	}
	if anchor == nil || now < anchor.notBefore || now > anchor.expiresAt ||
		!containsText(anchor.methods, approval.signature.descriptor.method) {
		return approvalSkipped
	}
	if outcome := evaluator.authentic(approval); outcome != approvalCounted {
		return outcome
	}
	if anchor.status.kind == 1 {
		err := principalStatusIn(
			anchor.status, approval.approver, statusRequired,
			func(issuer string) bool { return approverOutOfScope(context.principalSnapshot.trust, issuer) },
			context, evaluator.controls,
		)
		var failure semanticFailure
		if errors.As(err, &failure) {
			if failure.decision == "indeterminate" {
				return approvalPending
			}
			return approvalSkipped
		}
		if err != nil {
			return approvalSkipped
		}
	}
	return approvalCounted
}

// authentic verifies the approval's signature as principal control verifies a
// statement's, over the object type 10 preimage with the canonical action's
// profile, purpose assertion, signing time not_before, and the approval's own
// evidence. A result principal control maps to indeterminate is pending; any
// other failure, or consumed evidence that differs from the approval's, is
// skipped.
func (evaluator *approvalEvaluator) authentic(approval *signedApproval) approvalOutcome {
	descriptor := approval.signature.descriptor
	preimage := signingPreimage(
		approvalObjectKind, evaluator.canonical.profile, approval.statementRaw, descriptor.raw,
	)
	control, err := verifyControl(
		descriptor.method, approval.approver, descriptor, approvalPurposeAssertion,
		approval.notBefore, preimage, approval.evidence, evaluator.context, evaluator.adapters,
	)
	if err != nil {
		var failure semanticFailure
		if errors.As(err, &failure) && failure.decision == "indeterminate" {
			return approvalPending
		}
		return approvalSkipped
	}
	if len(control.consumed) != len(approval.evidence) {
		return approvalSkipped
	}
	consumed := append([][]byte(nil), control.consumed...)
	sort.Slice(consumed, func(left, right int) bool {
		return bytes.Compare(consumed[left], consumed[right]) < 0
	})
	for index, object := range approval.evidence {
		if !bytes.Equal(consumed[index], object.id) {
			return approvalSkipped
		}
	}
	message := preimage
	if control.signatureMessage != nil {
		message = control.signatureMessage
	}
	if !verifySignature(descriptor.suite, control.key, message, approval.signature.signature) {
		return approvalSkipped
	}
	return approvalCounted
}

// approverOutOfScope reports whether a principal-status statement by issuer
// takes no part in an approver's status: an approver anchor is no trust
// anchor, so only an issuer the snapshot does not know, or one whose every
// rule has scope any, speaks about an approver. The decoder guarantees every
// rule naming one issuer carries the same scope.
func approverOutOfScope(trust []statusTrustRule, issuer string) bool {
	for _, rule := range trust {
		if rule.issuer == issuer {
			return rule.scope.kind != statusScopeAny
		}
	}
	return false
}

// chainApprovalRequirements collects the distinct requirements, by
// identifier, of every approval-requirement-v1 extension of the chain, root
// first, in first-appearance order. More than sixteen is
// resource-limit-exceeded.
func chainApprovalRequirements(chain []*signedGrant) ([]approvalRequirement, error) {
	var requirements []approvalRequirement
	seen := make(map[string]bool)
	for _, grant := range chain {
		for _, extension := range grant.extensions {
			if extension.id != approvalExtension {
				continue
			}
			decoded, err := decodeApprovalRequirements(extension.bytes)
			if err != nil {
				return nil, evaluateApprovalExtension(extension)
			}
			for _, requirement := range decoded {
				key := digestKey(requirement.id)
				if seen[key] {
					continue
				}
				seen[key] = true
				requirements = append(requirements, requirement)
			}
		}
	}
	if len(requirements) > maxApprovalRequirementChain {
		return nil, denied("resource-limit-exceeded")
	}
	return requirements, nil
}

// branchApprovals evaluates the grant-carried requirements of one chain. The
// per-chain bound and the per-verification bound on distinct requirements are
// both resource-limit-exceeded for the attempt that reaches them.
func branchApprovals(evaluator *approvalEvaluator, chain []*signedGrant) error {
	requirements, err := chainApprovalRequirements(chain)
	if err != nil {
		return err
	}
	err = evaluator.evaluateList(requirements)
	if errors.Is(err, errApprovalEvaluations) {
		return denied("resource-limit-exceeded")
	}
	return err
}
