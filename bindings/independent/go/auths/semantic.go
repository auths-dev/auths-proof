package auths

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// This file is an independent implementation of the Auths V1 semantic waist.
// It intentionally does not link to Rust, generated Rust schemas, or WASM.

type cborValue struct {
	major byte
	uint  uint64
	bytes []byte
	text  string
	array []*cborValue
	pairs []cborPair
	raw   []byte
}

type cborPair struct {
	key   *cborValue
	value *cborValue
}

type valueParser struct {
	data  []byte
	at    int
	items int
}

func decodeValue(data []byte) (*cborValue, error) {
	p := valueParser{data: data}
	value, err := p.item(1)
	if err != nil {
		return nil, err
	}
	if p.at != len(data) {
		return nil, errors.New("trailing CBOR bytes")
	}
	return value, nil
}

func (p *valueParser) item(depth int) (*cborValue, error) {
	if depth > maxDepth || p.items >= maxItems || p.at >= len(p.data) {
		return nil, errors.New("CBOR resource limit or truncation")
	}
	p.items++
	start := p.at
	initial := p.data[p.at]
	p.at++
	major, additional := initial>>5, initial&31
	argument, err := p.argument(additional)
	if err != nil {
		return nil, err
	}
	value := &cborValue{major: major, uint: argument}
	switch major {
	case 0, 1:
	case 2, 3:
		length, err := boundedLength(argument, len(p.data)-p.at)
		if err != nil {
			return nil, err
		}
		body := p.data[p.at : p.at+length]
		p.at += length
		if major == 2 {
			value.bytes = append([]byte(nil), body...)
		} else {
			if !utf8Valid(body) {
				return nil, errors.New("invalid CBOR UTF-8")
			}
			value.text = string(body)
		}
	case 4:
		length, err := boundedLength(argument, maxItems-p.items)
		if err != nil {
			return nil, err
		}
		value.array = make([]*cborValue, 0, length)
		for range length {
			child, err := p.item(depth + 1)
			if err != nil {
				return nil, err
			}
			value.array = append(value.array, child)
		}
	case 5:
		length, err := boundedLength(argument, (maxItems-p.items)/2)
		if err != nil {
			return nil, err
		}
		value.pairs = make([]cborPair, 0, length)
		var previous []byte
		for range length {
			key, err := p.item(depth + 1)
			if err != nil {
				return nil, err
			}
			if previous != nil {
				order := canonicalCompare(previous, key.raw)
				if order == 0 {
					return nil, errors.New("duplicate CBOR map key")
				}
				if order > 0 {
					return nil, errors.New("non-canonical CBOR map key order")
				}
			}
			previous = append(previous[:0], key.raw...)
			entry, err := p.item(depth + 1)
			if err != nil {
				return nil, err
			}
			value.pairs = append(value.pairs, cborPair{key: key, value: entry})
		}
	case 7:
		if additional != 20 && additional != 21 && additional != 22 {
			return nil, errors.New("unsupported CBOR simple or floating value")
		}
	default:
		return nil, errors.New("CBOR tags are not admitted")
	}
	value.raw = append([]byte(nil), p.data[start:p.at]...)
	return value, nil
}

func (p *valueParser) argument(additional byte) (uint64, error) {
	if additional < 24 {
		return uint64(additional), nil
	}
	width := 0
	switch additional {
	case 24:
		width = 1
	case 25:
		width = 2
	case 26:
		width = 4
	case 27:
		width = 8
	default:
		return 0, errors.New("indefinite or reserved CBOR argument")
	}
	if p.at+width > len(p.data) {
		return 0, errors.New("truncated CBOR argument")
	}
	var value uint64
	for _, octet := range p.data[p.at : p.at+width] {
		value = value<<8 | uint64(octet)
	}
	p.at += width
	if (width == 1 && value < 24) ||
		(width == 2 && value <= 0xff) ||
		(width == 4 && value <= 0xffff) ||
		(width == 8 && value <= 0xffffffff) {
		return 0, errors.New("non-minimal CBOR argument")
	}
	return value, nil
}

func utf8Valid(value []byte) bool {
	return bytes.Equal([]byte(string(value)), value)
}

func mapValue(value *cborValue, key uint64) (*cborValue, error) {
	if value == nil || value.major != 5 {
		return nil, errors.New("expected CBOR map")
	}
	for _, pair := range value.pairs {
		if pair.key.major == 0 && pair.key.uint == key {
			return pair.value, nil
		}
	}
	return nil, fmt.Errorf("missing CBOR map key %d", key)
}

func exactMap(value *cborValue, entries int) error {
	if value == nil || value.major != 5 || len(value.pairs) != entries {
		return fmt.Errorf("expected CBOR map with %d entries", entries)
	}
	for index, pair := range value.pairs {
		if pair.key.major != 0 || pair.key.uint != uint64(index) {
			return errors.New("unexpected CBOR map key")
		}
	}
	return nil
}

func textValue(value *cborValue) (string, error) {
	if value == nil || value.major != 3 {
		return "", errors.New("expected CBOR text")
	}
	return value.text, nil
}

func bytesValue(value *cborValue, length int) ([]byte, error) {
	if value == nil || value.major != 2 || (length >= 0 && len(value.bytes) != length) {
		return nil, errors.New("unexpected CBOR byte string")
	}
	return append([]byte(nil), value.bytes...), nil
}

func uintValue(value *cborValue) (uint64, error) {
	if value == nil || value.major != 0 {
		return 0, errors.New("expected CBOR unsigned integer")
	}
	return value.uint, nil
}

func arrayValue(value *cborValue) ([]*cborValue, error) {
	if value == nil || value.major != 4 {
		return nil, errors.New("expected CBOR array")
	}
	return value.array, nil
}

func optionalBytes(value *cborValue) ([]byte, error) {
	if value != nil && value.major == 7 && value.uint == 22 {
		return nil, nil
	}
	return bytesValue(value, 32)
}

type permission struct {
	capability string
	resource   string
}

type profile struct {
	id      string
	version uint64
}

type budget struct {
	algebra string
	value   uint64
}

type statusPolicy struct {
	kind   uint64
	method string
	maxAge uint64
}

type constraint struct {
	kind    uint64
	digests [][]byte
}

type signatureDescriptor struct {
	method             string
	verificationMethod string
	suite              string
	raw                []byte
}

type signatureEnvelope struct {
	descriptor signatureDescriptor
	signature  []byte
}

type criticalExtension struct {
	id    string
	bytes []byte
}

type signedGrant struct {
	statement *cborValue
	issuer    string
	subject   string
	profile   profile
	perms     []permission
	notBefore uint64
	expiresAt uint64
	audiences []string
	constraint
	budget         *budget
	remainingDepth uint64
	parent         []byte
	status         statusPolicy
	assurance      string
	extensions     []criticalExtension
	signature      signatureEnvelope
	id             []byte
}

type signedAction struct {
	envelope      *cborValue
	profile       profile
	mediaType     string
	bodyDigest    []byte
	permission    permission
	budget        *budget
	audience      string
	challenge     []byte
	notBefore     uint64
	expiresAt     uint64
	actor         string
	terminalGrant []byte
	planID        []byte
	channel       string
	proofRef      []byte
	attachments   []attachmentDescriptor
	extensions    []criticalExtension
	signature     signatureEnvelope
	id            []byte
}

type planNode struct {
	kind     uint64
	k        uint64
	proofRef []byte
	children []*planNode
	raw      []byte
}

type evidenceObject struct {
	id        []byte
	kind      string
	mediaType string
	body      []byte
}

type statementReference struct {
	kind uint64
	id   []byte
}

func (value statementReference) key() string {
	return fmt.Sprintf("%d:%x", value.kind, value.id)
}

type controlBinding struct {
	statement statementReference
	evidence  [][]byte
}

type principalStatus struct {
	statement  *cborValue
	method     string
	principal  string
	purpose    string
	state      uint64
	sequence   uint64
	observedAt uint64
	validUntil uint64
	issuer     string
	signature  signatureEnvelope
	id         []byte
}

type grantStatus struct {
	statement  *cborValue
	method     string
	grantID    []byte
	state      uint64
	sequence   uint64
	observedAt uint64
	validUntil uint64
	issuer     string
	signature  signatureEnvelope
	id         []byte
}

type proofBundle struct {
	raw             []byte
	grants          []*signedGrant
	actions         []*signedAction
	plan            *planNode
	evidence        []*evidenceObject
	bindings        []*controlBinding
	principalStatus []*principalStatus
	grantStatus     []*grantStatus
	attachments     []attachmentDescriptor
	canonicalBody   []byte
}

type trustAnchor struct {
	principal   string
	methods     []string
	profiles    []profile
	permissions []permission
	namespaces  []string
	audiences   []string
	notBefore   uint64
	expiresAt   uint64
	budget      *budget
	maxDepth    uint64
	assurance   string
	status      statusPolicy
}

type assuranceRequirement struct {
	role       uint64
	claim      string
	maximumAge *uint64
}

type statusTrustRule struct {
	method          string
	issuer          string
	minimumSequence uint64
}

type statusSnapshot[T any] struct {
	observedAt  uint64
	validUntil  uint64
	statements  []*T
	checkpoints [][]byte
	trust       []statusTrustRule
}

type verifierContext struct {
	raw               []byte
	anchors           []*trustAnchor
	registryManifest  []byte
	principalMethods  []string
	signatureSuites   []string
	evidenceTypes     []string
	principalStatuses []string
	grantStatuses     []string
	assuranceClaims   []string
	budgetAlgebras    []string
	resourceMatchers  []string
	extensions        []string
	profiles          []profile
	profilePolicies   []string
	expectedAudience  string
	expectedChallenge []byte
	evaluationTime    uint64
	assuranceID       string
	assurance         []assuranceRequirement
	principalSnapshot statusSnapshot[principalStatus]
	grantSnapshot     statusSnapshot[grantStatus]
	resourceMatcher   string
	profilePolicy     string
	channelPolicy     string
	limits            [24]uint64
}

type canonicalAction struct {
	body       []byte
	profile    profile
	mediaType  string
	permission permission
	budget     *budget
	detached   []detachedAttachment
}

type attachmentDescriptor struct {
	digest        []byte
	mediaType     string
	byteLength    uint64
	disposition   string
	encrypted     bool
	required      bool
	opaqueAllowed bool
	raw           []byte
}

type detachedAttachment struct {
	digest []byte
	bytes  []byte
}

type semanticFailure struct {
	decision string
	code     string
}

func (failure semanticFailure) Error() string {
	return failure.decision + ":" + failure.code
}

func denied(code string) error {
	return semanticFailure{decision: "denied", code: code}
}

func indeterminate(code string) error {
	return semanticFailure{decision: "indeterminate", code: code}
}

func profileValue(value *cborValue) (profile, error) {
	if err := exactMap(value, 2); err != nil {
		return profile{}, err
	}
	id, err := mapValue(value, 0)
	if err != nil {
		return profile{}, err
	}
	version, err := mapValue(value, 1)
	if err != nil {
		return profile{}, err
	}
	idText, err := textValue(id)
	if err != nil {
		return profile{}, err
	}
	versionNumber, err := uintValue(version)
	if err != nil || versionNumber == 0 || versionNumber > 65535 {
		return profile{}, errors.New("invalid profile")
	}
	return profile{id: idText, version: versionNumber}, nil
}

func permissionValue(value *cborValue) (permission, error) {
	if err := exactMap(value, 2); err != nil {
		return permission{}, err
	}
	capability, err := mapValue(value, 0)
	if err != nil {
		return permission{}, err
	}
	resource, err := mapValue(value, 1)
	if err != nil {
		return permission{}, err
	}
	capabilityText, err := textValue(capability)
	if err != nil {
		return permission{}, err
	}
	resourceText, err := textValue(resource)
	if err != nil {
		return permission{}, err
	}
	return permission{capability: capabilityText, resource: resourceText}, nil
}

func budgetValue(value *cborValue) (*budget, error) {
	if value.major == 7 && value.uint == 22 {
		return nil, nil
	}
	if err := exactMap(value, 2); err != nil {
		return nil, err
	}
	algebraValue, _ := mapValue(value, 0)
	numberValue, _ := mapValue(value, 1)
	algebra, err := textValue(algebraValue)
	if err != nil {
		return nil, err
	}
	number, err := uintValue(numberValue)
	if err != nil {
		return nil, err
	}
	return &budget{algebra: algebra, value: number}, nil
}

func statusPolicyValue(value *cborValue) (statusPolicy, error) {
	kindValue, err := mapValue(value, 0)
	if err != nil {
		return statusPolicy{}, err
	}
	kind, err := uintValue(kindValue)
	if err != nil {
		return statusPolicy{}, err
	}
	if kind == 0 && len(value.pairs) == 1 {
		return statusPolicy{}, nil
	}
	if kind != 1 || len(value.pairs) != 3 {
		return statusPolicy{}, errors.New("invalid status policy")
	}
	methodValue, _ := mapValue(value, 1)
	ageValue, _ := mapValue(value, 2)
	method, err := textValue(methodValue)
	if err != nil {
		return statusPolicy{}, err
	}
	age, err := uintValue(ageValue)
	if err != nil || age == 0 {
		return statusPolicy{}, errors.New("invalid status age")
	}
	return statusPolicy{kind: 1, method: method, maxAge: age}, nil
}

func constraintValue(value *cborValue) (constraint, error) {
	kindValue, err := mapValue(value, 0)
	if err != nil {
		return constraint{}, err
	}
	kind, err := uintValue(kindValue)
	if err != nil {
		return constraint{}, err
	}
	result := constraint{kind: kind}
	switch kind {
	case 0:
		if len(value.pairs) != 1 {
			return constraint{}, errors.New("invalid any-body constraint")
		}
	case 1:
		if len(value.pairs) != 2 {
			return constraint{}, errors.New("invalid exact-body constraint")
		}
		digestValue, _ := mapValue(value, 1)
		digest, err := bytesValue(digestValue, 32)
		if err != nil {
			return constraint{}, err
		}
		result.digests = [][]byte{digest}
	case 2:
		if len(value.pairs) != 2 {
			return constraint{}, errors.New("invalid allowed-body constraint")
		}
		digestsValue, _ := mapValue(value, 1)
		digests, err := arrayValue(digestsValue)
		if err != nil || len(digests) == 0 {
			return constraint{}, errors.New("invalid allowed-body digests")
		}
		for _, item := range digests {
			digest, err := bytesValue(item, 32)
			if err != nil {
				return constraint{}, err
			}
			result.digests = append(result.digests, digest)
		}
	default:
		return constraint{}, errors.New("unknown action constraint")
	}
	return result, nil
}

func textArray(value *cborValue) ([]string, error) {
	values, err := arrayValue(value)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(values))
	for _, item := range values {
		text, err := textValue(item)
		if err != nil {
			return nil, err
		}
		result = append(result, text)
	}
	return result, nil
}

func permissionArray(value *cborValue) ([]permission, error) {
	values, err := arrayValue(value)
	if err != nil {
		return nil, err
	}
	result := make([]permission, 0, len(values))
	for _, item := range values {
		entry, err := permissionValue(item)
		if err != nil {
			return nil, err
		}
		result = append(result, entry)
	}
	return result, nil
}

func extensionValues(value *cborValue) ([]criticalExtension, error) {
	values, err := arrayValue(value)
	if err != nil {
		return nil, err
	}
	result := make([]criticalExtension, 0, len(values))
	for _, item := range values {
		if err := exactMap(item, 2); err != nil {
			return nil, err
		}
		idValue, _ := mapValue(item, 0)
		bytesValueNode, _ := mapValue(item, 1)
		id, err := textValue(idValue)
		if err != nil {
			return nil, err
		}
		rawBytes, err := bytesValue(bytesValueNode, -1)
		if err != nil {
			return nil, err
		}
		result = append(result, criticalExtension{id: id, bytes: rawBytes})
	}
	return result, nil
}

func signatureValue(value *cborValue) (signatureEnvelope, error) {
	if err := exactMap(value, 2); err != nil {
		return signatureEnvelope{}, err
	}
	descriptorValue, _ := mapValue(value, 0)
	if err := exactMap(descriptorValue, 3); err != nil {
		return signatureEnvelope{}, err
	}
	methodValue, _ := mapValue(descriptorValue, 0)
	verificationValue, _ := mapValue(descriptorValue, 1)
	suiteValue, _ := mapValue(descriptorValue, 2)
	method, err := textValue(methodValue)
	if err != nil {
		return signatureEnvelope{}, err
	}
	verificationMethod, err := textValue(verificationValue)
	if err != nil {
		return signatureEnvelope{}, err
	}
	suite, err := textValue(suiteValue)
	if err != nil {
		return signatureEnvelope{}, err
	}
	signatureValue, _ := mapValue(value, 1)
	signature, err := bytesValue(signatureValue, -1)
	if err != nil || len(signature) == 0 {
		return signatureEnvelope{}, errors.New("invalid signature bytes")
	}
	return signatureEnvelope{
		descriptor: signatureDescriptor{
			method:             method,
			verificationMethod: verificationMethod,
			suite:              suite,
			raw:                append([]byte(nil), descriptorValue.raw...),
		},
		signature: signature,
	}, nil
}

func decodeGrant(value *cborValue) (*signedGrant, error) {
	if err := exactMap(value, 2); err != nil {
		return nil, err
	}
	statement, _ := mapValue(value, 0)
	if err := exactMap(statement, 16); err != nil {
		return nil, err
	}
	versionValue, _ := mapValue(statement, 0)
	version, err := uintValue(versionValue)
	if err != nil || version != 1 {
		return nil, errors.New("unsupported grant protocol")
	}
	issuerValue, _ := mapValue(statement, 1)
	subjectValue, _ := mapValue(statement, 2)
	profileIDValue, _ := mapValue(statement, 3)
	profileVersionValue, _ := mapValue(statement, 4)
	permissionsValue, _ := mapValue(statement, 5)
	notBeforeValue, _ := mapValue(statement, 6)
	expiresValue, _ := mapValue(statement, 7)
	audiencesValue, _ := mapValue(statement, 8)
	constraintNode, _ := mapValue(statement, 9)
	budgetNode, _ := mapValue(statement, 10)
	depthValue, _ := mapValue(statement, 11)
	parentValue, _ := mapValue(statement, 12)
	statusValue, _ := mapValue(statement, 13)
	assuranceValue, _ := mapValue(statement, 14)
	extensionsValue, _ := mapValue(statement, 15)
	issuer, err := textValue(issuerValue)
	if err != nil {
		return nil, err
	}
	subject, err := textValue(subjectValue)
	if err != nil {
		return nil, err
	}
	profileID, err := textValue(profileIDValue)
	if err != nil {
		return nil, err
	}
	profileVersion, err := uintValue(profileVersionValue)
	if err != nil {
		return nil, err
	}
	perms, err := permissionArray(permissionsValue)
	if err != nil || len(perms) == 0 {
		return nil, errors.New("invalid grant permissions")
	}
	notBefore, err := uintValue(notBeforeValue)
	if err != nil {
		return nil, err
	}
	expiresAt, err := uintValue(expiresValue)
	if err != nil || notBefore > expiresAt {
		return nil, errors.New("invalid grant validity")
	}
	audiences, err := textArray(audiencesValue)
	if err != nil || len(audiences) == 0 {
		return nil, errors.New("invalid grant audiences")
	}
	bodyConstraint, err := constraintValue(constraintNode)
	if err != nil {
		return nil, err
	}
	grantBudget, err := budgetValue(budgetNode)
	if err != nil {
		return nil, err
	}
	remainingDepth, err := uintValue(depthValue)
	if err != nil || remainingDepth > 65535 {
		return nil, errors.New("invalid grant depth")
	}
	parent, err := optionalBytes(parentValue)
	if err != nil {
		return nil, err
	}
	status, err := statusPolicyValue(statusValue)
	if err != nil {
		return nil, err
	}
	assurance, err := textValue(assuranceValue)
	if err != nil {
		return nil, err
	}
	extensions, err := extensionValues(extensionsValue)
	if err != nil {
		return nil, err
	}
	signatureNode, _ := mapValue(value, 1)
	signature, err := signatureValue(signatureNode)
	if err != nil {
		return nil, err
	}
	return &signedGrant{
		statement:      statement,
		issuer:         issuer,
		subject:        subject,
		profile:        profile{id: profileID, version: profileVersion},
		perms:          perms,
		notBefore:      notBefore,
		expiresAt:      expiresAt,
		audiences:      audiences,
		constraint:     bodyConstraint,
		budget:         grantBudget,
		remainingDepth: remainingDepth,
		parent:         parent,
		status:         status,
		assurance:      assurance,
		extensions:     extensions,
		signature:      signature,
	}, nil
}

func booleanValue(value *cborValue) (bool, error) {
	if value.major != 7 || (value.uint != 20 && value.uint != 21) {
		return false, errors.New("expected CBOR boolean")
	}
	return value.uint == 21, nil
}

func decodeAttachment(value *cborValue) (attachmentDescriptor, error) {
	if err := exactMap(value, 7); err != nil {
		return attachmentDescriptor{}, err
	}
	digest, err := bytesValue(mustMap(value, 0), 32)
	if err != nil {
		return attachmentDescriptor{}, err
	}
	mediaType, err := textValue(mustMap(value, 1))
	if err != nil {
		return attachmentDescriptor{}, err
	}
	byteLength, err := uintValue(mustMap(value, 2))
	if err != nil {
		return attachmentDescriptor{}, err
	}
	disposition, err := textValue(mustMap(value, 3))
	if err != nil {
		return attachmentDescriptor{}, err
	}
	encrypted, err := booleanValue(mustMap(value, 4))
	if err != nil {
		return attachmentDescriptor{}, err
	}
	required, err := booleanValue(mustMap(value, 5))
	if err != nil {
		return attachmentDescriptor{}, err
	}
	opaqueAllowed, err := booleanValue(mustMap(value, 6))
	if err != nil {
		return attachmentDescriptor{}, err
	}
	return attachmentDescriptor{
		digest: digest, mediaType: mediaType, byteLength: byteLength,
		disposition: disposition, encrypted: encrypted, required: required,
		opaqueAllowed: opaqueAllowed, raw: append([]byte(nil), value.raw...),
	}, nil
}

func decodeAction(value *cborValue) (*signedAction, error) {
	if err := exactMap(value, 2); err != nil {
		return nil, err
	}
	envelope, _ := mapValue(value, 0)
	if err := exactMap(envelope, 19); err != nil {
		return nil, err
	}
	versionValue, _ := mapValue(envelope, 0)
	version, err := uintValue(versionValue)
	if err != nil || version != 1 {
		return nil, errors.New("unsupported action protocol")
	}
	profileIDValue, _ := mapValue(envelope, 1)
	profileVersionValue, _ := mapValue(envelope, 2)
	mediaValue, _ := mapValue(envelope, 3)
	bodyValue, _ := mapValue(envelope, 4)
	capabilityValue, _ := mapValue(envelope, 5)
	resourceValue, _ := mapValue(envelope, 6)
	budgetNode, _ := mapValue(envelope, 7)
	audienceValue, _ := mapValue(envelope, 8)
	challengeValue, _ := mapValue(envelope, 9)
	notBeforeValue, _ := mapValue(envelope, 10)
	expiresValue, _ := mapValue(envelope, 11)
	actorValue, _ := mapValue(envelope, 12)
	terminalValue, _ := mapValue(envelope, 13)
	planValue, _ := mapValue(envelope, 14)
	channelValue, _ := mapValue(envelope, 15)
	proofRefValue, _ := mapValue(envelope, 16)
	attachmentsValue, _ := mapValue(envelope, 17)
	attachmentNodes, err := arrayValue(attachmentsValue)
	if err != nil {
		return nil, err
	}
	attachments := make([]attachmentDescriptor, 0, len(attachmentNodes))
	for _, node := range attachmentNodes {
		attachment, err := decodeAttachment(node)
		if err != nil {
			return nil, err
		}
		attachments = append(attachments, attachment)
	}
	extensionsValue, _ := mapValue(envelope, 18)
	profileID, err := textValue(profileIDValue)
	if err != nil {
		return nil, err
	}
	profileVersion, err := uintValue(profileVersionValue)
	if err != nil {
		return nil, err
	}
	mediaType, err := textValue(mediaValue)
	if err != nil {
		return nil, err
	}
	bodyDigest, err := bytesValue(bodyValue, 32)
	if err != nil {
		return nil, err
	}
	capability, err := textValue(capabilityValue)
	if err != nil {
		return nil, err
	}
	resource, err := textValue(resourceValue)
	if err != nil {
		return nil, err
	}
	actionBudget, err := budgetValue(budgetNode)
	if err != nil {
		return nil, err
	}
	audience, err := textValue(audienceValue)
	if err != nil {
		return nil, err
	}
	challenge, err := bytesValue(challengeValue, 32)
	if err != nil {
		return nil, err
	}
	notBefore, err := uintValue(notBeforeValue)
	if err != nil {
		return nil, err
	}
	expiresAt, err := uintValue(expiresValue)
	if err != nil || notBefore > expiresAt {
		return nil, errors.New("invalid action validity")
	}
	actor, err := textValue(actorValue)
	if err != nil {
		return nil, err
	}
	terminal, err := optionalBytes(terminalValue)
	if err != nil {
		return nil, err
	}
	planID, err := bytesValue(planValue, 32)
	if err != nil {
		return nil, err
	}
	channel, err := textValue(channelValue)
	if err != nil {
		return nil, err
	}
	proofRef, err := bytesValue(proofRefValue, 32)
	if err != nil {
		return nil, err
	}
	extensions, err := extensionValues(extensionsValue)
	if err != nil {
		return nil, err
	}
	signatureNode, _ := mapValue(value, 1)
	signature, err := signatureValue(signatureNode)
	if err != nil {
		return nil, err
	}
	return &signedAction{
		envelope:      envelope,
		profile:       profile{id: profileID, version: profileVersion},
		mediaType:     mediaType,
		bodyDigest:    bodyDigest,
		permission:    permission{capability: capability, resource: resource},
		budget:        actionBudget,
		audience:      audience,
		challenge:     challenge,
		notBefore:     notBefore,
		expiresAt:     expiresAt,
		actor:         actor,
		terminalGrant: terminal,
		planID:        planID,
		channel:       channel,
		proofRef:      proofRef,
		attachments:   attachments,
		extensions:    extensions,
		signature:     signature,
	}, nil
}

func decodePlan(value *cborValue, depth int, limits [24]uint64) (*planNode, int, error) {
	if uint64(depth) > limits[4] {
		return nil, 0, denied("resource-limit-exceeded")
	}
	kindValue, err := mapValue(value, 0)
	if err != nil {
		return nil, 0, err
	}
	kind, err := uintValue(kindValue)
	if err != nil {
		return nil, 0, err
	}
	result := &planNode{kind: kind, raw: append([]byte(nil), value.raw...)}
	switch kind {
	case 0:
		if len(value.pairs) != 2 {
			return nil, 0, errors.New("invalid proof plan")
		}
		referenceValue, _ := mapValue(value, 1)
		result.proofRef, err = bytesValue(referenceValue, 32)
		return result, 1, err
	case 1, 2:
		if len(value.pairs) != 2 {
			return nil, 0, errors.New("invalid compound plan")
		}
		childrenValue, _ := mapValue(value, 1)
		children, err := arrayValue(childrenValue)
		if err != nil || len(children) == 0 || uint64(len(children)) > limits[5] {
			return nil, 0, denied("resource-limit-exceeded")
		}
		leaves := 0
		for _, child := range children {
			decoded, count, err := decodePlan(child, depth+1, limits)
			if err != nil {
				return nil, 0, err
			}
			result.children = append(result.children, decoded)
			leaves += count
		}
		return result, leaves, nil
	case 3:
		if len(value.pairs) != 3 {
			return nil, 0, errors.New("invalid threshold plan")
		}
		kValue, _ := mapValue(value, 1)
		result.k, err = uintValue(kValue)
		if err != nil {
			return nil, 0, err
		}
		childrenValue, _ := mapValue(value, 2)
		children, err := arrayValue(childrenValue)
		if err != nil || len(children) == 0 || result.k == 0 ||
			result.k > uint64(len(children)) || uint64(len(children)) > limits[5] {
			return nil, 0, denied("resource-limit-exceeded")
		}
		leaves := 0
		for _, child := range children {
			decoded, count, err := decodePlan(child, depth+1, limits)
			if err != nil {
				return nil, 0, err
			}
			result.children = append(result.children, decoded)
			leaves += count
		}
		return result, leaves, nil
	default:
		return nil, 0, errors.New("unknown authorization plan")
	}
}

func domainHash(kind uint16, canonical []byte) []byte {
	hash := sha256.New()
	hash.Write([]byte("AUTHS-ID"))
	var protocol [2]byte
	binary.BigEndian.PutUint16(protocol[:], 1)
	hash.Write(protocol[:])
	binary.BigEndian.PutUint16(protocol[:], kind)
	hash.Write(protocol[:])
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(canonical)))
	hash.Write(length[:])
	hash.Write(canonical)
	return hash.Sum(nil)
}

func signingPreimage(kind uint16, profile profile, object []byte, descriptor []byte) []byte {
	signingObject := make([]byte, 0, len(object)+len(descriptor)+4)
	signingObject = append(signingObject, 0xa2, 0x00)
	signingObject = append(signingObject, object...)
	signingObject = append(signingObject, 0x01)
	signingObject = append(signingObject, descriptor...)
	output := append([]byte(nil), []byte("AUTHS")...)
	var short [2]byte
	binary.BigEndian.PutUint16(short[:], 1)
	output = append(output, short[:]...)
	binary.BigEndian.PutUint16(short[:], kind)
	output = append(output, short[:]...)
	binary.BigEndian.PutUint16(short[:], uint16(len(profile.id)))
	output = append(output, short[:]...)
	output = append(output, profile.id...)
	binary.BigEndian.PutUint16(short[:], uint16(profile.version))
	output = append(output, short[:]...)
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(signingObject)))
	output = append(output, length[:]...)
	output = append(output, signingObject...)
	return output
}

func containsText(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func equalProfile(left, right profile) bool {
	return left.id == right.id && left.version == right.version
}

func equalBudget(left, right *budget) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.algebra == right.algebra && left.value == right.value
}

func equalPermission(left, right permission) bool {
	return left.capability == right.capability && left.resource == right.resource
}

func encodeCBORText(value string) []byte {
	return append(encodeCBORHead(3, uint64(len(value))), []byte(value)...)
}

func encodeCBORBytes(value []byte) []byte {
	return append(encodeCBORHead(2, uint64(len(value))), value...)
}

func encodeCBORHead(major byte, value uint64) []byte {
	switch {
	case value < 24:
		return []byte{major<<5 | byte(value)}
	case value <= 0xff:
		return []byte{major<<5 | 24, byte(value)}
	case value <= 0xffff:
		return []byte{major<<5 | 25, byte(value >> 8), byte(value)}
	case value <= 0xffffffff:
		return []byte{major<<5 | 26, byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}
	default:
		result := []byte{major<<5 | 27}
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], value)
		return append(result, encoded[:]...)
	}
}

func evidenceContent(object *evidenceObject) []byte {
	output := []byte{0xa3, 0x00}
	output = append(output, encodeCBORText(object.kind)...)
	output = append(output, 0x01)
	output = append(output, encodeCBORText(object.mediaType)...)
	output = append(output, 0x02)
	output = append(output, encodeCBORBytes(object.body)...)
	return output
}

func verifySignature(suite string, key, message, signature []byte) bool {
	switch suite {
	case "ed25519-v1":
		return len(key) == ed25519.PublicKeySize &&
			len(signature) == ed25519.SignatureSize &&
			ed25519.Verify(ed25519.PublicKey(key), message, signature)
	case "p256-sha256-v1":
		if len(signature) != 64 {
			return false
		}
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), key)
		if x == nil {
			return false
		}
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		halfOrder := new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)
		if s.Cmp(halfOrder) > 0 {
			return false
		}
		digest := sha256.Sum256(message)
		return ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, digest[:], r, s)
	default:
		return false
	}
}

func decodeHex(value string) ([]byte, error) {
	return hex.DecodeString(value)
}

func decodeBase64URL(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

func jsonObject(data []byte) (map[string]any, error) {
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, err
	}
	return value, nil
}

func stringField(value map[string]any, key string) (string, error) {
	text, ok := value[key].(string)
	if !ok {
		return "", fmt.Errorf("missing JSON string %s", key)
	}
	return text, nil
}

func bytesEqual(left, right []byte) bool {
	return bytes.Equal(left, right)
}

func digestKey(value []byte) string {
	return hex.EncodeToString(value)
}

func stringSetSubset(child, parent []string) bool {
	for _, item := range child {
		if !containsText(parent, item) {
			return false
		}
	}
	return true
}

func permissionSubset(child, parent []permission) bool {
	for _, item := range child {
		found := false
		for _, candidate := range parent {
			if equalPermission(item, candidate) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func profileContains(values []profile, expected profile) bool {
	for _, value := range values {
		if equalProfile(value, expected) {
			return true
		}
	}
	return false
}

func constraintAllows(value constraint, digest []byte) bool {
	if value.kind == 0 {
		return true
	}
	for _, allowed := range value.digests {
		if bytesEqual(allowed, digest) {
			return true
		}
	}
	return false
}

func constraintAttenuates(child, parent constraint) bool {
	if parent.kind == 0 {
		return true
	}
	if child.kind == 0 {
		return false
	}
	for _, digest := range child.digests {
		found := false
		for _, allowed := range parent.digests {
			if bytesEqual(digest, allowed) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func budgetAttenuates(child, parent *budget) bool {
	if parent == nil {
		return true
	}
	return child != nil && child.algebra == parent.algebra && child.value <= parent.value
}

func budgetCovers(ceiling, requested *budget) bool {
	if requested == nil || ceiling == nil {
		return true
	}
	return ceiling.algebra == requested.algebra && requested.value <= ceiling.value
}

func statusAttenuates(child, parent statusPolicy) bool {
	if parent.kind == 0 {
		return true
	}
	return child.kind == 1 && child.method == parent.method && child.maxAge <= parent.maxAge
}

func purposeName(kind uint64) string {
	switch kind {
	case 0:
		return "capability-delegation"
	case 1:
		return "capability-invocation"
	default:
		return "assertion"
	}
}

func hasPrefix(value, prefix string) bool {
	return strings.HasPrefix(value, prefix)
}
