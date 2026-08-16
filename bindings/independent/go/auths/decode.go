package auths

import (
	"bytes"
	"errors"
	"fmt"
)

func decodePrincipalStatus(value *cborValue) (*principalStatus, error) {
	if err := exactMap(value, 2); err != nil {
		return nil, err
	}
	statement, _ := mapValue(value, 0)
	if err := exactMap(statement, 10); err != nil {
		return nil, err
	}
	values := make([]*cborValue, 10)
	for index := range values {
		values[index], _ = mapValue(statement, uint64(index))
	}
	version, err := uintValue(values[0])
	if err != nil || version != 1 {
		return nil, errors.New("unsupported principal-status protocol")
	}
	method, err := textValue(values[1])
	if err != nil {
		return nil, err
	}
	principal, err := textValue(values[2])
	if err != nil {
		return nil, err
	}
	purpose, err := textValue(values[3])
	if err != nil {
		return nil, err
	}
	state, err := uintValue(values[4])
	if err != nil || state > 2 {
		return nil, errors.New("invalid principal state")
	}
	sequence, err := uintValue(values[5])
	if err != nil {
		return nil, err
	}
	observedAt, err := uintValue(values[6])
	if err != nil {
		return nil, err
	}
	validUntil, err := uintValue(values[7])
	if err != nil || observedAt > validUntil {
		return nil, errors.New("invalid principal-status validity")
	}
	issuer, err := textValue(values[8])
	if err != nil {
		return nil, err
	}
	if _, err := extensionValues(values[9]); err != nil {
		return nil, err
	}
	signatureNode, _ := mapValue(value, 1)
	signature, err := signatureValue(signatureNode)
	if err != nil {
		return nil, err
	}
	return &principalStatus{
		statement:  statement,
		method:     method,
		principal:  principal,
		purpose:    purpose,
		state:      state,
		sequence:   sequence,
		observedAt: observedAt,
		validUntil: validUntil,
		issuer:     issuer,
		signature:  signature,
		id:         domainHash(5, statement.raw),
	}, nil
}

func decodeGrantStatus(value *cborValue) (*grantStatus, error) {
	if err := exactMap(value, 2); err != nil {
		return nil, err
	}
	statement, _ := mapValue(value, 0)
	if err := exactMap(statement, 9); err != nil {
		return nil, err
	}
	values := make([]*cborValue, 9)
	for index := range values {
		values[index], _ = mapValue(statement, uint64(index))
	}
	version, err := uintValue(values[0])
	if err != nil || version != 1 {
		return nil, errors.New("unsupported grant-status protocol")
	}
	method, err := textValue(values[1])
	if err != nil {
		return nil, err
	}
	grantID, err := bytesValue(values[2], 32)
	if err != nil {
		return nil, err
	}
	state, err := uintValue(values[3])
	if err != nil || state > 2 {
		return nil, errors.New("invalid grant state")
	}
	sequence, err := uintValue(values[4])
	if err != nil {
		return nil, err
	}
	observedAt, err := uintValue(values[5])
	if err != nil {
		return nil, err
	}
	validUntil, err := uintValue(values[6])
	if err != nil || observedAt > validUntil {
		return nil, errors.New("invalid grant-status validity")
	}
	issuer, err := textValue(values[7])
	if err != nil {
		return nil, err
	}
	if _, err := extensionValues(values[8]); err != nil {
		return nil, err
	}
	signatureNode, _ := mapValue(value, 1)
	signature, err := signatureValue(signatureNode)
	if err != nil {
		return nil, err
	}
	return &grantStatus{
		statement:  statement,
		method:     method,
		grantID:    grantID,
		state:      state,
		sequence:   sequence,
		observedAt: observedAt,
		validUntil: validUntil,
		issuer:     issuer,
		signature:  signature,
		id:         domainHash(6, statement.raw),
	}, nil
}

func decodeStatementReference(value *cborValue) (statementReference, error) {
	if err := exactMap(value, 2); err != nil {
		return statementReference{}, err
	}
	kindValue, _ := mapValue(value, 0)
	idValue, _ := mapValue(value, 1)
	kind, err := uintValue(kindValue)
	if err != nil || kind > 3 {
		return statementReference{}, errors.New("invalid statement-reference kind")
	}
	id, err := bytesValue(idValue, 32)
	if err != nil {
		return statementReference{}, err
	}
	return statementReference{kind: kind, id: id}, nil
}

func decodeEvidence(value *cborValue, maximum uint64) (*evidenceObject, error) {
	if err := exactMap(value, 4); err != nil {
		return nil, err
	}
	idValue, _ := mapValue(value, 0)
	kindValue, _ := mapValue(value, 1)
	mediaValue, _ := mapValue(value, 2)
	bodyValue, _ := mapValue(value, 3)
	id, err := bytesValue(idValue, 32)
	if err != nil {
		return nil, err
	}
	kind, err := textValue(kindValue)
	if err != nil {
		return nil, err
	}
	media, err := textValue(mediaValue)
	if err != nil {
		return nil, err
	}
	body, err := bytesValue(bodyValue, -1)
	if err != nil || len(body) == 0 || uint64(len(body)) > maximum {
		return nil, denied("resource-limit-exceeded")
	}
	object := &evidenceObject{id: id, kind: kind, mediaType: media, body: body}
	if !bytes.Equal(domainHash(4, evidenceContent(object)), id) {
		return nil, denied("digest-mismatch")
	}
	return object, nil
}

func decodeBinding(value *cborValue, maximum uint64) (*controlBinding, error) {
	if err := exactMap(value, 2); err != nil {
		return nil, err
	}
	statementValue, _ := mapValue(value, 0)
	evidenceValue, _ := mapValue(value, 1)
	statement, err := decodeStatementReference(statementValue)
	if err != nil {
		return nil, err
	}
	evidenceNodes, err := arrayValue(evidenceValue)
	if err != nil || len(evidenceNodes) == 0 || uint64(len(evidenceNodes)) > maximum {
		return nil, denied("resource-limit-exceeded")
	}
	result := &controlBinding{statement: statement}
	var previous []byte
	for _, node := range evidenceNodes {
		id, err := bytesValue(node, 32)
		if err != nil {
			return nil, err
		}
		if previous != nil && bytes.Compare(previous, id) >= 0 {
			return nil, errors.New("unsorted binding evidence")
		}
		previous = id
		result.evidence = append(result.evidence, id)
	}
	return result, nil
}

func decodeBundle(data []byte, limits [27]uint64) (*proofBundle, error) {
	if uint64(len(data)) > limits[0] {
		return nil, denied("resource-limit-exceeded")
	}
	root, err := decodeValue(data)
	if err != nil {
		if bytes.Contains([]byte(err.Error()), []byte("non-minimal")) ||
			bytes.Contains([]byte(err.Error()), []byte("non-canonical")) {
			return nil, denied("non-canonical-proof")
		}
		return nil, denied("malformed-proof")
	}
	if err := exactMap(root, 10); err != nil {
		return nil, denied("malformed-proof")
	}
	header, _ := mapValue(root, 0)
	if err := exactMap(header, 2); err != nil {
		return nil, denied("malformed-proof")
	}
	versionValue, _ := mapValue(header, 0)
	flagsValue, _ := mapValue(header, 1)
	version, versionErr := uintValue(versionValue)
	flags, flagsErr := uintValue(flagsValue)
	if versionErr != nil || flagsErr != nil || flags != 0 {
		return nil, denied("malformed-proof")
	}
	if version != 1 {
		return nil, indeterminate("unsupported-protocol")
	}
	result := &proofBundle{raw: append([]byte(nil), data...)}
	grantsValue, _ := mapValue(root, 1)
	grantNodes, err := arrayValue(grantsValue)
	if err != nil || uint64(len(grantNodes)) > limits[3] {
		return nil, denied("resource-limit-exceeded")
	}
	for _, node := range grantNodes {
		grant, err := decodeGrant(node)
		if err != nil {
			return nil, semanticDecodeFailure(err)
		}
		grant.id = domainHash(1, grant.statement.raw)
		result.grants = append(result.grants, grant)
	}
	actionsValue, _ := mapValue(root, 2)
	actionNodes, err := arrayValue(actionsValue)
	if err != nil || len(actionNodes) == 0 || uint64(len(actionNodes)) > limits[4] {
		return nil, denied("resource-limit-exceeded")
	}
	for _, node := range actionNodes {
		action, err := decodeAction(node)
		if err != nil {
			return nil, semanticDecodeFailure(err)
		}
		action.id = domainHash(2, action.envelope.raw)
		result.actions = append(result.actions, action)
	}
	planValue, _ := mapValue(root, 3)
	var leaves int
	result.plan, leaves, err = decodePlan(planValue, 1, limits)
	if err != nil {
		return nil, semanticDecodeFailure(err)
	}
	if uint64(leaves) > limits[5] {
		return nil, denied("resource-limit-exceeded")
	}
	evidenceValue, _ := mapValue(root, 4)
	evidenceNodes, err := arrayValue(evidenceValue)
	if err != nil || uint64(len(evidenceNodes)) > limits[8] {
		return nil, denied("resource-limit-exceeded")
	}
	for _, node := range evidenceNodes {
		evidence, err := decodeEvidence(node, limits[9])
		if err != nil {
			return nil, semanticDecodeFailure(err)
		}
		result.evidence = append(result.evidence, evidence)
	}
	bindingsValue, _ := mapValue(root, 5)
	bindingNodes, err := arrayValue(bindingsValue)
	if err != nil || uint64(len(bindingNodes)) > limits[10] {
		return nil, denied("resource-limit-exceeded")
	}
	for _, node := range bindingNodes {
		binding, err := decodeBinding(node, limits[22])
		if err != nil {
			return nil, semanticDecodeFailure(err)
		}
		result.bindings = append(result.bindings, binding)
	}
	principalStatusValue, _ := mapValue(root, 6)
	principalStatusNodes, err := arrayValue(principalStatusValue)
	if err != nil || uint64(len(principalStatusNodes)) > limits[11] {
		return nil, denied("resource-limit-exceeded")
	}
	for _, node := range principalStatusNodes {
		status, err := decodePrincipalStatus(node)
		if err != nil {
			return nil, semanticDecodeFailure(err)
		}
		result.principalStatus = append(result.principalStatus, status)
	}
	grantStatusValue, _ := mapValue(root, 7)
	grantStatusNodes, err := arrayValue(grantStatusValue)
	if err != nil || uint64(len(grantStatusNodes)) > limits[12] {
		return nil, denied("resource-limit-exceeded")
	}
	for _, node := range grantStatusNodes {
		status, err := decodeGrantStatus(node)
		if err != nil {
			return nil, semanticDecodeFailure(err)
		}
		result.grantStatus = append(result.grantStatus, status)
	}
	attachmentsValue, _ := mapValue(root, 8)
	attachmentNodes, err := arrayValue(attachmentsValue)
	if err != nil || uint64(len(attachmentNodes)) > limits[13] {
		return nil, denied("resource-limit-exceeded")
	}
	for _, node := range attachmentNodes {
		attachment, err := decodeAttachment(node)
		if err != nil {
			return nil, semanticDecodeFailure(err)
		}
		result.attachments = append(result.attachments, attachment)
	}
	bodyValue, _ := mapValue(root, 9)
	if bodyValue.major == 7 && bodyValue.uint == 22 {
		result.canonicalBody = nil
	} else {
		result.canonicalBody, err = bytesValue(bodyValue, -1)
		if err != nil || uint64(len(result.canonicalBody)) > limits[23] {
			return nil, denied("resource-limit-exceeded")
		}
	}
	return result, nil
}

func semanticDecodeFailure(err error) error {
	var failure semanticFailure
	if errors.As(err, &failure) {
		return failure
	}
	return denied("malformed-proof")
}

func decodeAnchor(value *cborValue) (*trustAnchor, error) {
	if err := exactMap(value, 13); err != nil {
		return nil, err
	}
	nodes := make([]*cborValue, 13)
	for index := range nodes {
		nodes[index], _ = mapValue(value, uint64(index))
	}
	principal, err := textValue(nodes[1])
	if err != nil {
		return nil, err
	}
	methods, err := textArray(nodes[2])
	if err != nil {
		return nil, err
	}
	profileNodes, err := arrayValue(nodes[3])
	if err != nil {
		return nil, err
	}
	profiles := make([]profile, 0, len(profileNodes))
	for _, node := range profileNodes {
		item, err := profileValue(node)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, item)
	}
	permissions, err := permissionArray(nodes[4])
	if err != nil {
		return nil, err
	}
	namespaces, err := textArray(nodes[5])
	if err != nil {
		return nil, err
	}
	audiences, err := textArray(nodes[6])
	if err != nil {
		return nil, err
	}
	notBefore, err := uintValue(nodes[7])
	if err != nil {
		return nil, err
	}
	expiresAt, err := uintValue(nodes[8])
	if err != nil || notBefore > expiresAt {
		return nil, errors.New("invalid anchor validity")
	}
	anchorBudget, err := budgetValue(nodes[9])
	if err != nil {
		return nil, err
	}
	maxDepth, err := uintValue(nodes[10])
	if err != nil {
		return nil, err
	}
	assurance, err := textValue(nodes[11])
	if err != nil {
		return nil, err
	}
	status, err := statusPolicyValue(nodes[12])
	if err != nil {
		return nil, err
	}
	return &trustAnchor{
		principal:   principal,
		methods:     methods,
		profiles:    profiles,
		permissions: permissions,
		namespaces:  namespaces,
		audiences:   audiences,
		notBefore:   notBefore,
		expiresAt:   expiresAt,
		budget:      anchorBudget,
		maxDepth:    maxDepth,
		assurance:   assurance,
		status:      status,
	}, nil
}

func decodeProfileArray(value *cborValue) ([]profile, error) {
	nodes, err := arrayValue(value)
	if err != nil {
		return nil, err
	}
	result := make([]profile, 0, len(nodes))
	for _, node := range nodes {
		item, err := profileValue(node)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, nil
}

func decodePrincipalSnapshot(value *cborValue) (statusSnapshot[principalStatus], error) {
	if err := exactMap(value, 6); err != nil {
		return statusSnapshot[principalStatus]{}, err
	}
	observedValue, _ := mapValue(value, 1)
	validValue, _ := mapValue(value, 2)
	statementsValue, _ := mapValue(value, 3)
	checkpointsValue, _ := mapValue(value, 4)
	trustValue, _ := mapValue(value, 5)
	observed, err := uintValue(observedValue)
	if err != nil {
		return statusSnapshot[principalStatus]{}, err
	}
	valid, err := uintValue(validValue)
	if err != nil {
		return statusSnapshot[principalStatus]{}, err
	}
	nodes, err := arrayValue(statementsValue)
	if err != nil {
		return statusSnapshot[principalStatus]{}, err
	}
	result := statusSnapshot[principalStatus]{observedAt: observed, validUntil: valid}
	for _, node := range nodes {
		statement, err := decodePrincipalStatus(node)
		if err != nil {
			return statusSnapshot[principalStatus]{}, err
		}
		result.statements = append(result.statements, statement)
	}
	result.checkpoints, err = digestArray(checkpointsValue)
	if err == nil {
		result.trust, err = decodeStatusTrust(trustValue)
	}
	return result, err
}

func decodeGrantSnapshot(value *cborValue) (statusSnapshot[grantStatus], error) {
	if err := exactMap(value, 6); err != nil {
		return statusSnapshot[grantStatus]{}, err
	}
	observedValue, _ := mapValue(value, 1)
	validValue, _ := mapValue(value, 2)
	statementsValue, _ := mapValue(value, 3)
	checkpointsValue, _ := mapValue(value, 4)
	trustValue, _ := mapValue(value, 5)
	observed, err := uintValue(observedValue)
	if err != nil {
		return statusSnapshot[grantStatus]{}, err
	}
	valid, err := uintValue(validValue)
	if err != nil {
		return statusSnapshot[grantStatus]{}, err
	}
	nodes, err := arrayValue(statementsValue)
	if err != nil {
		return statusSnapshot[grantStatus]{}, err
	}
	result := statusSnapshot[grantStatus]{observedAt: observed, validUntil: valid}
	for _, node := range nodes {
		statement, err := decodeGrantStatus(node)
		if err != nil {
			return statusSnapshot[grantStatus]{}, err
		}
		result.statements = append(result.statements, statement)
	}
	result.checkpoints, err = digestArray(checkpointsValue)
	if err == nil {
		result.trust, err = decodeStatusTrust(trustValue)
	}
	return result, err
}

func decodeStatusTrust(value *cborValue) ([]statusTrustRule, error) {
	nodes, err := arrayValue(value)
	if err != nil {
		return nil, err
	}
	result := make([]statusTrustRule, 0, len(nodes))
	for _, node := range nodes {
		if err := exactMap(node, 3); err != nil {
			return nil, err
		}
		method, err := textValue(mustMap(node, 0))
		if err != nil {
			return nil, err
		}
		issuer, err := textValue(mustMap(node, 1))
		if err != nil {
			return nil, err
		}
		minimumSequence, err := uintValue(mustMap(node, 2))
		if err != nil {
			return nil, err
		}
		result = append(result, statusTrustRule{
			method: method, issuer: issuer, minimumSequence: minimumSequence,
		})
	}
	return result, nil
}

func digestArray(value *cborValue) ([][]byte, error) {
	nodes, err := arrayValue(value)
	if err != nil {
		return nil, err
	}
	result := make([][]byte, 0, len(nodes))
	for _, node := range nodes {
		digest, err := bytesValue(node, 32)
		if err != nil {
			return nil, err
		}
		result = append(result, digest)
	}
	return result, nil
}

func decodeContext(data []byte) (*verifierContext, error) {
	root, err := decodeValue(data)
	if err != nil {
		return nil, err
	}
	if err := exactMap(root, 14); err != nil {
		return nil, err
	}
	result := &verifierContext{raw: append([]byte(nil), data...)}
	limits := mustMap(root, 0)
	if err := exactMap(limits, 27); err != nil {
		return nil, err
	}
	for index := range result.limits {
		result.limits[index], err = uintValue(mustMap(limits, uint64(index)))
		if err != nil {
			return nil, err
		}
	}
	result.configuration, err = bytesValue(mustMap(root, 1), 32)
	if err != nil {
		return nil, err
	}
	composition := mustMap(root, 2)
	if err := exactMap(composition, 4); err != nil {
		return nil, err
	}
	expectedPlan := mustMap(composition, 0)
	if !(expectedPlan.major == 7 && expectedPlan.uint == 22) {
		result.composition.expectedPlan, err = bytesValue(expectedPlan, 32)
		if err != nil {
			return nil, err
		}
	}
	result.composition.minimumAuthorizedBranches, err = uintValue(mustMap(composition, 1))
	if err != nil {
		return nil, err
	}
	result.composition.minimumDistinctActors, err = uintValue(mustMap(composition, 2))
	if err != nil {
		return nil, err
	}
	result.composition.minimumDistinctRoots, err = uintValue(mustMap(composition, 3))
	if err != nil {
		return nil, err
	}
	if result.composition.minimumAuthorizedBranches == 0 ||
		result.composition.minimumDistinctActors == 0 ||
		result.composition.minimumDistinctRoots == 0 ||
		result.composition.minimumDistinctActors > result.composition.minimumAuthorizedBranches ||
		result.composition.minimumDistinctRoots > result.composition.minimumAuthorizedBranches {
		return nil, errors.New("invalid composition requirement")
	}
	anchorsValue, _ := mapValue(root, 3)
	anchorNodes, err := arrayValue(anchorsValue)
	if err != nil || len(anchorNodes) == 0 {
		return nil, errors.New("invalid trust anchors")
	}
	for _, node := range anchorNodes {
		anchor, err := decodeAnchor(node)
		if err != nil {
			return nil, err
		}
		result.anchors = append(result.anchors, anchor)
	}
	registries, _ := mapValue(root, 4)
	if err := exactMap(registries, 14); err != nil {
		return nil, err
	}
	if result.registryManifest, err = bytesValue(mustMap(registries, 0), 32); err != nil {
		return nil, err
	}
	if result.principalMethods, err = textArray(mustMap(registries, 1)); err != nil {
		return nil, err
	}
	if result.signatureSuites, err = textArray(mustMap(registries, 2)); err != nil {
		return nil, err
	}
	if result.evidenceTypes, err = textArray(mustMap(registries, 3)); err != nil {
		return nil, err
	}
	if result.principalStatuses, err = textArray(mustMap(registries, 4)); err != nil {
		return nil, err
	}
	if result.grantStatuses, err = textArray(mustMap(registries, 5)); err != nil {
		return nil, err
	}
	if result.assuranceClaims, err = textArray(mustMap(registries, 6)); err != nil {
		return nil, err
	}
	if result.resourceMatchers, err = textArray(mustMap(registries, 8)); err != nil {
		return nil, err
	}
	if result.budgetAlgebras, err = textArray(mustMap(registries, 9)); err != nil {
		return nil, err
	}
	if result.extensions, err = textArray(mustMap(registries, 10)); err != nil {
		return nil, err
	}
	if result.profiles, err = decodeProfileArray(mustMap(registries, 11)); err != nil {
		return nil, err
	}
	if result.profilePolicies, err = textArray(mustMap(registries, 12)); err != nil {
		return nil, err
	}
	if result.budgetFreeProfiles, err = decodeProfileArray(mustMap(registries, 13)); err != nil {
		return nil, err
	}
	result.expectedAudience, err = textValue(mustMap(root, 5))
	if err != nil {
		return nil, err
	}
	result.expectedChallenge, err = bytesValue(mustMap(root, 6), 32)
	if err != nil {
		return nil, err
	}
	result.evaluationTime, err = uintValue(mustMap(root, 7))
	if err != nil {
		return nil, err
	}
	assurance, _ := mapValue(root, 8)
	if err := exactMap(assurance, 2); err != nil {
		return nil, err
	}
	result.assuranceID, err = textValue(mustMap(assurance, 0))
	if err != nil {
		return nil, err
	}
	requirementNodes, err := arrayValue(mustMap(assurance, 1))
	if err != nil {
		return nil, err
	}
	for _, node := range requirementNodes {
		if err := exactMap(node, 8); err != nil {
			return nil, err
		}
		role, err := uintValue(mustMap(node, 0))
		if err != nil {
			return nil, err
		}
		claim, err := textValue(mustMap(node, 1))
		if err != nil {
			return nil, err
		}
		maximumNode := mustMap(node, 6)
		var maximum *uint64
		if !(maximumNode.major == 7 && maximumNode.uint == 22) {
			value, err := uintValue(maximumNode)
			if err != nil {
				return nil, err
			}
			maximum = &value
		}
		quantifier, err := uintValue(mustMap(node, 7))
		if err != nil || quantifier > 1 {
			return nil, errors.New("invalid assurance quantifier")
		}
		result.assurance = append(result.assurance, assuranceRequirement{
			role: role, claim: claim, maximumAge: maximum, quantifier: quantifier,
		})
	}
	result.principalSnapshot, err = decodePrincipalSnapshot(mustMap(root, 9))
	if err != nil {
		return nil, err
	}
	result.grantSnapshot, err = decodeGrantSnapshot(mustMap(root, 10))
	if err != nil {
		return nil, err
	}
	result.resourceMatcher, err = textValue(mustMap(root, 11))
	if err != nil {
		return nil, err
	}
	result.profilePolicy, err = textValue(mustMap(root, 12))
	if err != nil {
		return nil, err
	}
	result.channelPolicy, err = textValue(mustMap(root, 13))
	if err != nil {
		return nil, err
	}
	return result, nil
}

func mustMap(value *cborValue, key uint64) *cborValue {
	result, err := mapValue(value, key)
	if err != nil {
		panic(fmt.Sprintf("validated map omitted key %d", key))
	}
	return result
}
