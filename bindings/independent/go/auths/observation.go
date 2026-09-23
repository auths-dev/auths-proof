package auths

// Independent evidence-conditioned authority: observation requirements carried
// by grants, signed observations attached to the action, and the per-branch
// observation stage. Written from the V1 specification, not from the Rust
// verifier.

import (
	"bytes"
	"errors"
	"sort"
)

const (
	observationExtension          = "observation-requirement-v1"
	observationMediaType          = "application/vnd.auths.observation.v1+cbor"
	maxRequirementsPerGrant       = 8
	maxRequirementsPerChain       = 32
	maxObservationConditions      = 16
	maxMemberValues               = 16
	maxObservationFacts           = 16
	maxObservationEvidence        = 4
	maxObservationAttachments     = 32
	maxObservationBytes           = 4096
	maxObservationAgeSeconds      = 86400
	maxFactBytes                  = 64
	maxFactTextBytes              = 256
	maxObserverAnchors            = 32
	observationObjectKind         = 9
	observationPurposeAssertion   = 2
	observationSubjectResource    = 0
	observationSubjectActionFact  = 1
	conditionEqLiteral            = 0
	conditionEqAction             = 1
	conditionUintRange            = 2
	conditionMember               = 3
	factKindUint, factKindBytes   = 0, 1
	factKindText                  = 2
	observationFactNameMaxBytes   = 128
	observationIdentifierMaxBytes = 128
)

var errObservationLimit = errors.New("observation limit exceeded")

type factValue struct {
	kind  int
	uint  uint64
	bytes []byte
	text  string
}

func (value factValue) equal(other factValue) bool {
	if value.kind != other.kind {
		return false
	}
	switch value.kind {
	case factKindUint:
		return value.uint == other.uint
	case factKindBytes:
		return bytes.Equal(value.bytes, other.bytes)
	default:
		return value.text == other.text
	}
}

type observationCondition struct {
	name    string
	tag     uint64
	literal factValue
	action  string
	lo, hi  uint64
	members []factValue
}

type observationRequirement struct {
	raw         []byte
	anchor      string
	schema      string
	subjectKind uint64
	subject     string
	maxAge      uint64
	conditions  []observationCondition
}

type observerAnchor struct {
	id         string
	principal  string
	methods    []string
	schemas    []string
	namespaces []string
	notBefore  uint64
	expiresAt  uint64
}

type observationFact struct {
	name  string
	value factValue
}

type signedObservation struct {
	digest       []byte
	observer     string
	schema       string
	subject      string
	observedAt   uint64
	facts        []observationFact
	statementRaw []byte
	signature    signatureEnvelope
	evidence     []*evidenceObject
	authentic    *bool
}

func boundedIdentifier(value *cborValue, maximum int) (string, error) {
	text, err := textValue(value)
	if err != nil || len(text) == 0 || len(text) > maximum {
		return "", errors.New("invalid bounded identifier")
	}
	for _, character := range text {
		if character <= 0x20 || character == 0x7f || (character >= 0x80 && character <= 0x9f) ||
			character == 0x85 || character == 0xa0 || character == 0x1680 ||
			(character >= 0x2000 && character <= 0x200a) || character == 0x2028 ||
			character == 0x2029 || character == 0x202f || character == 0x205f ||
			character == 0x3000 {
			return "", errors.New("invalid bounded identifier")
		}
	}
	return text, nil
}

func decodeFactValue(value *cborValue) (factValue, error) {
	switch value.major {
	case 0:
		return factValue{kind: factKindUint, uint: value.uint}, nil
	case 2:
		if len(value.bytes) > maxFactBytes {
			return factValue{}, errObservationLimit
		}
		return factValue{kind: factKindBytes, bytes: value.bytes}, nil
	case 3:
		if len(value.text) > maxFactTextBytes {
			return factValue{}, errObservationLimit
		}
		return factValue{kind: factKindText, text: value.text}, nil
	default:
		return factValue{}, errors.New("invalid fact value")
	}
}

func boundedArray(value *cborValue, minimum, maximum int) ([]*cborValue, error) {
	items, err := arrayValue(value)
	if err != nil {
		return nil, err
	}
	if len(items) > maximum {
		return nil, errObservationLimit
	}
	if len(items) < minimum {
		return nil, errors.New("array below its minimum")
	}
	return items, nil
}

func decodeCondition(value *cborValue) (observationCondition, error) {
	tagValue, err := mapValue(value, 0)
	if err != nil {
		return observationCondition{}, err
	}
	tag, err := uintValue(tagValue)
	if err != nil {
		return observationCondition{}, err
	}
	entries := 3
	if tag == conditionUintRange {
		entries = 4
	}
	if err := exactMap(value, entries); err != nil {
		return observationCondition{}, err
	}
	name, err := boundedIdentifier(mustMap(value, 1), observationFactNameMaxBytes)
	if err != nil {
		return observationCondition{}, err
	}
	condition := observationCondition{name: name, tag: tag}
	operand := mustMap(value, 2)
	switch tag {
	case conditionEqLiteral:
		condition.literal, err = decodeFactValue(operand)
	case conditionEqAction:
		condition.action, err = boundedIdentifier(operand, observationFactNameMaxBytes)
	case conditionUintRange:
		if condition.lo, err = uintValue(operand); err == nil {
			condition.hi, err = uintValue(mustMap(value, 3))
		}
		if err == nil && condition.lo > condition.hi {
			err = errors.New("inverted range")
		}
	case conditionMember:
		var items []*cborValue
		items, err = boundedArray(operand, 1, maxMemberValues)
		for _, item := range items {
			if err != nil {
				break
			}
			var member factValue
			member, err = decodeFactValue(item)
			for _, previous := range condition.members {
				if err == nil && previous.equal(member) {
					err = errors.New("duplicate member value")
				}
			}
			condition.members = append(condition.members, member)
		}
	default:
		err = errors.New("unknown condition atom")
	}
	return condition, err
}

func decodeRequirement(value *cborValue) (observationRequirement, error) {
	if err := exactMap(value, 5); err != nil {
		return observationRequirement{}, err
	}
	result := observationRequirement{raw: value.raw}
	var err error
	if result.anchor, err = boundedIdentifier(mustMap(value, 0), observationIdentifierMaxBytes); err != nil {
		return result, err
	}
	if result.schema, err = boundedIdentifier(mustMap(value, 1), observationIdentifierMaxBytes); err != nil {
		return result, err
	}
	subject := mustMap(value, 2)
	if err := exactMap(subject, 2); err != nil {
		return result, err
	}
	if result.subjectKind, err = uintValue(mustMap(subject, 0)); err != nil {
		return result, err
	}
	switch result.subjectKind {
	case observationSubjectResource:
		result.subject, err = boundedIdentifier(mustMap(subject, 1), 1024)
	case observationSubjectActionFact:
		result.subject, err = boundedIdentifier(mustMap(subject, 1), observationFactNameMaxBytes)
	default:
		err = errors.New("unknown subject kind")
	}
	if err != nil {
		return result, err
	}
	if result.maxAge, err = uintValue(mustMap(value, 3)); err != nil {
		return result, err
	}
	conditions, err := boundedArray(mustMap(value, 4), 1, maxObservationConditions)
	if err != nil {
		return result, err
	}
	for _, node := range conditions {
		condition, err := decodeCondition(node)
		if err != nil {
			return result, err
		}
		result.conditions = append(result.conditions, condition)
	}
	if result.maxAge == 0 || result.maxAge > maxObservationAgeSeconds {
		return result, errors.New("maximum age out of range")
	}
	return result, nil
}

// decodeRequirements returns errObservationLimit for a count or size bound and
// another error for any other invalid extension bytes.
func decodeRequirements(data []byte) ([]observationRequirement, error) {
	root, err := decodeValue(data)
	if err != nil {
		return nil, err
	}
	nodes, err := boundedArray(root, 1, maxRequirementsPerGrant)
	if err != nil {
		return nil, err
	}
	requirements := make([]observationRequirement, 0, len(nodes))
	for _, node := range nodes {
		requirement, err := decodeRequirement(node)
		if err != nil {
			return nil, err
		}
		for _, previous := range requirements {
			if bytes.Equal(previous.raw, requirement.raw) {
				return nil, errors.New("duplicate observation requirement")
			}
		}
		requirements = append(requirements, requirement)
	}
	return requirements, nil
}

func requirementFailure(err error) error {
	if errors.Is(err, errObservationLimit) {
		return denied("resource-limit-exceeded")
	}
	return denied("local-policy-denied")
}

func stageFailure(err error) error {
	if errors.Is(err, errObservationLimit) {
		return denied("resource-limit-exceeded")
	}
	var failure semanticFailure
	if errors.As(err, &failure) {
		return failure
	}
	return denied("malformed-proof")
}

func decodeObserverAnchors(value *cborValue) ([]*observerAnchor, error) {
	nodes, err := arrayValue(value)
	if err != nil {
		return nil, err
	}
	if len(nodes) > maxObserverAnchors {
		return nil, denied("resource-limit-exceeded")
	}
	anchors := make([]*observerAnchor, 0, len(nodes))
	for _, node := range nodes {
		if err := exactMap(node, 7); err != nil {
			return nil, err
		}
		anchor := &observerAnchor{}
		if anchor.id, err = textValue(mustMap(node, 0)); err != nil {
			return nil, err
		}
		if anchor.principal, err = textValue(mustMap(node, 1)); err != nil {
			return nil, err
		}
		if anchor.methods, err = textArray(mustMap(node, 2)); err != nil {
			return nil, err
		}
		if anchor.schemas, err = textArray(mustMap(node, 3)); err != nil {
			return nil, err
		}
		if anchor.namespaces, err = textArray(mustMap(node, 4)); err != nil {
			return nil, err
		}
		if anchor.notBefore, err = uintValue(mustMap(node, 5)); err != nil {
			return nil, err
		}
		if anchor.expiresAt, err = uintValue(mustMap(node, 6)); err != nil {
			return nil, err
		}
		if len(anchor.methods) == 0 || len(anchor.schemas) == 0 ||
			len(anchor.namespaces) == 0 || anchor.notBefore > anchor.expiresAt {
			return nil, errors.New("invalid observer anchor")
		}
		if len(anchors) > 0 && anchors[len(anchors)-1].id >= anchor.id {
			return nil, errors.New("observer anchors are not strictly ordered")
		}
		anchors = append(anchors, anchor)
	}
	return anchors, nil
}

func decodeObservation(data []byte, limits [27]uint64) (*signedObservation, error) {
	if len(data) > maxObservationBytes {
		return nil, errObservationLimit
	}
	root, err := decodeValue(data)
	if err != nil {
		return nil, err
	}
	if err := exactMap(root, 3); err != nil {
		return nil, err
	}
	statement := mustMap(root, 0)
	if err := exactMap(statement, 6); err != nil {
		return nil, err
	}
	result := &signedObservation{statementRaw: statement.raw}
	if version, err := uintValue(mustMap(statement, 0)); err != nil || version != 1 {
		return nil, errors.New("unsupported observation version")
	}
	if result.observer, err = textValue(mustMap(statement, 1)); err != nil {
		return nil, err
	}
	if result.schema, err = boundedIdentifier(mustMap(statement, 2), observationIdentifierMaxBytes); err != nil {
		return nil, err
	}
	if result.subject, err = boundedIdentifier(mustMap(statement, 3), 1024); err != nil {
		return nil, err
	}
	if result.observedAt, err = uintValue(mustMap(statement, 4)); err != nil {
		return nil, err
	}
	facts, err := boundedArray(mustMap(statement, 5), 1, maxObservationFacts)
	if err != nil {
		return nil, err
	}
	for _, node := range facts {
		if err := exactMap(node, 2); err != nil {
			return nil, err
		}
		name, err := boundedIdentifier(mustMap(node, 0), observationFactNameMaxBytes)
		if err != nil {
			return nil, err
		}
		value, err := decodeFactValue(mustMap(node, 1))
		if err != nil {
			return nil, err
		}
		if len(result.facts) > 0 && result.facts[len(result.facts)-1].name >= name {
			return nil, errors.New("observation facts are not strictly ordered")
		}
		result.facts = append(result.facts, observationFact{name: name, value: value})
	}
	if result.signature, err = signatureValue(mustMap(root, 1)); err != nil {
		return nil, err
	}
	if uint64(len(result.signature.signature)) > limits[16] {
		return nil, errObservationLimit
	}
	evidence, err := boundedArray(mustMap(root, 2), 0, maxObservationEvidence)
	if err != nil {
		return nil, err
	}
	for _, node := range evidence {
		object, err := decodeEvidence(node, limits[9])
		if err != nil {
			return nil, err
		}
		if len(result.evidence) > 0 &&
			bytes.Compare(result.evidence[len(result.evidence)-1].id, object.id) >= 0 {
			return nil, errors.New("observation evidence is not strictly ordered")
		}
		result.evidence = append(result.evidence, object)
	}
	return result, nil
}

// validateObservationAttachments enforces the per-action observation bounds.
func validateObservationAttachments(action *signedAction) error {
	count := 0
	for _, descriptor := range action.attachments {
		if descriptor.mediaType != observationMediaType {
			continue
		}
		count++
		if count > maxObservationAttachments || descriptor.byteLength > maxObservationBytes {
			return denied("resource-limit-exceeded")
		}
	}
	return nil
}

func evaluateObservationExtension(extension criticalExtension) error {
	if _, err := decodeRequirements(extension.bytes); err != nil {
		return requirementFailure(err)
	}
	return nil
}

func chainRequirements(chain []*signedGrant) ([]observationRequirement, error) {
	var requirements []observationRequirement
	for _, grant := range chain {
		for _, extension := range grant.extensions {
			if extension.id != observationExtension {
				continue
			}
			decoded, err := decodeRequirements(extension.bytes)
			if err != nil {
				return nil, requirementFailure(err)
			}
			for _, requirement := range decoded {
				duplicate := false
				for _, existing := range requirements {
					duplicate = duplicate || bytes.Equal(existing.raw, requirement.raw)
				}
				if !duplicate {
					requirements = append(requirements, requirement)
				}
			}
		}
	}
	if len(requirements) > maxRequirementsPerChain {
		return nil, denied("resource-limit-exceeded")
	}
	return requirements, nil
}

// requireParentRequirements denies a child grant that drops or alters any of
// its parent's observation requirements.
func requireParentRequirements(parent, child *signedGrant) error {
	parentRequirements, err := chainRequirements([]*signedGrant{parent})
	if err != nil {
		return err
	}
	childRequirements, _ := chainRequirements([]*signedGrant{child})
	for _, requirement := range parentRequirements {
		kept := false
		for _, candidate := range childRequirements {
			kept = kept || bytes.Equal(candidate.raw, requirement.raw)
		}
		if !kept {
			return denied("observation-requirement-dropped")
		}
	}
	return nil
}

type observationStage struct {
	chain     []*signedGrant
	root      string
	action    *signedAction
	canonical canonicalAction
	context   *verifierContext
	adapters  adapterContext
}

func (stage observationStage) inAuthorityChain(principal string) bool {
	if principal == stage.root || principal == stage.action.actor {
		return true
	}
	for _, grant := range stage.chain {
		if principal == grant.issuer || principal == grant.subject {
			return true
		}
	}
	return false
}

func (stage observationStage) candidates() ([]*signedObservation, error) {
	var candidates []*signedObservation
	for _, descriptor := range stage.action.attachments {
		if descriptor.mediaType != observationMediaType {
			continue
		}
		for _, attachment := range stage.canonical.detached {
			if !bytes.Equal(attachment.digest, descriptor.digest) {
				continue
			}
			observation, err := decodeObservation(attachment.bytes, stage.context.limits)
			if err != nil {
				return nil, stageFailure(err)
			}
			observation.digest = descriptor.digest
			candidates = append(candidates, observation)
		}
	}
	sort.Slice(candidates, func(left, right int) bool {
		return bytes.Compare(candidates[left].digest, candidates[right].digest) < 0
	})
	return candidates, nil
}

func (stage observationStage) evaluate() error {
	requirements, err := chainRequirements(stage.chain)
	if err != nil || len(requirements) == 0 {
		return err
	}
	anchors := make([]*observerAnchor, len(requirements))
	for index, requirement := range requirements {
		for _, anchor := range stage.context.observerAnchors {
			if anchor.id == requirement.anchor {
				anchors[index] = anchor
			}
		}
		if anchors[index] != nil && stage.inAuthorityChain(anchors[index].principal) {
			return denied("observer-in-authority-chain")
		}
	}
	candidates, err := stage.candidates()
	if err != nil {
		return err
	}
	var unavailable error
	for index, requirement := range requirements {
		err := stage.requirement(requirement, anchors[index], candidates)
		var failure semanticFailure
		if errors.As(err, &failure) && failure.decision == "denied" {
			return failure
		}
		if err != nil && unavailable == nil {
			unavailable = err
		}
	}
	return unavailable
}

// requirement evaluates one requirement. The core registry's exact-v1 profile
// policy, the only one this verifier implements, defines no action facts.
func (stage observationStage) requirement(
	requirement observationRequirement,
	anchor *observerAnchor,
	candidates []*signedObservation,
) error {
	if anchor == nil {
		return indeterminate("observation-missing")
	}
	if requirement.subjectKind == observationSubjectActionFact {
		return indeterminate("observation-action-fact-unavailable")
	}
	for _, condition := range requirement.conditions {
		if condition.tag == conditionEqAction {
			return indeterminate("observation-action-fact-unavailable")
		}
	}
	anyEligible := false
	for _, candidate := range candidates {
		if !stage.eligible(requirement, anchor, candidate) {
			continue
		}
		anyEligible = true
		if conditionsHold(requirement.conditions, candidate.facts) {
			return nil
		}
	}
	if anyEligible {
		return denied("observation-condition-false")
	}
	return indeterminate("observation-missing")
}

func (stage observationStage) eligible(
	requirement observationRequirement,
	anchor *observerAnchor,
	candidate *signedObservation,
) bool {
	now := stage.context.evaluationTime
	if candidate.observer != anchor.principal ||
		candidate.schema != requirement.schema ||
		!containsText(anchor.schemas, requirement.schema) ||
		candidate.subject != requirement.subject ||
		candidate.observedAt > now ||
		now-candidate.observedAt > requirement.maxAge ||
		candidate.observedAt < anchor.notBefore ||
		candidate.observedAt > anchor.expiresAt ||
		!containsText(anchor.methods, candidate.signature.descriptor.method) {
		return false
	}
	inNamespace := false
	for _, namespace := range anchor.namespaces {
		inNamespace = inNamespace || uriNamespaceMatches(namespace, candidate.subject)
	}
	if !inNamespace {
		return false
	}
	if candidate.authentic == nil {
		authentic := stage.authentic(candidate)
		candidate.authentic = &authentic
	}
	return *candidate.authentic
}

func (stage observationStage) authentic(candidate *signedObservation) bool {
	descriptor := candidate.signature.descriptor
	preimage := signingPreimage(
		observationObjectKind, profile{}, candidate.statementRaw, descriptor.raw,
	)
	control, err := verifyControl(
		descriptor.method, candidate.observer, descriptor, observationPurposeAssertion,
		candidate.observedAt, preimage, candidate.evidence, stage.context, stage.adapters,
	)
	if err != nil || len(control.consumed) != len(candidate.evidence) {
		return false
	}
	consumed := append([][]byte(nil), control.consumed...)
	sort.Slice(consumed, func(left, right int) bool {
		return bytes.Compare(consumed[left], consumed[right]) < 0
	})
	for index, object := range candidate.evidence {
		if !bytes.Equal(consumed[index], object.id) {
			return false
		}
	}
	message := preimage
	if control.signatureMessage != nil {
		message = control.signatureMessage
	}
	return verifySignature(descriptor.suite, control.key, message, candidate.signature.signature)
}

func lookupFact(facts []observationFact, name string) (factValue, bool) {
	for _, fact := range facts {
		if fact.name == name {
			return fact.value, true
		}
	}
	return factValue{}, false
}

func conditionsHold(conditions []observationCondition, facts []observationFact) bool {
	for _, condition := range conditions {
		observed, present := lookupFact(facts, condition.name)
		if !present {
			return false
		}
		holds := false
		switch condition.tag {
		case conditionEqLiteral:
			holds = observed.equal(condition.literal)
		case conditionUintRange:
			holds = observed.kind == factKindUint &&
				observed.uint >= condition.lo && observed.uint <= condition.hi
		case conditionMember:
			for _, member := range condition.members {
				holds = holds || observed.equal(member)
			}
		}
		if !holds {
			return false
		}
	}
	return true
}
