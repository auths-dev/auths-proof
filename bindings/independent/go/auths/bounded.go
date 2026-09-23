package auths

// Independent bounded-policy commitments: the core shape of the
// bounded-policy-commitment-v1 grant critical extension and its link law.
// Written from the V1 specification, not from the Rust verifier.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const (
	boundedPolicyExtension        = "bounded-policy-commitment-v1"
	maxBoundedPolicyBytes         = 4096
	maxPolicyIdentifierBytes      = 128
	maxPolicyCanonicalizationSize = 64
	maxExtensionBytes             = 65536
	boundedPolicyDigestDomain     = "auths.bounded-policy.v1"
	boundedPolicyLinkDomain       = "auths.bounded-policy-commitment.v1"
)

var errBoundedPolicyLimit = errors.New("bounded-policy limit exceeded")

type boundedPolicy struct {
	parent []byte
}

// domainCommitment is SHA-256 over the commitment prefix, protocol version,
// the length-framed domain, and the length-framed payload.
func domainCommitment(domain string, payload []byte) []byte {
	hash := sha256.New()
	hash.Write([]byte("AUTHS-COMMITMENT"))
	var short [2]byte
	binary.BigEndian.PutUint16(short[:], 1)
	hash.Write(short[:])
	binary.BigEndian.PutUint16(short[:], uint16(len(domain)))
	hash.Write(short[:])
	hash.Write([]byte(domain))
	var long [8]byte
	binary.BigEndian.PutUint64(long[:], uint64(len(payload)))
	hash.Write(long[:])
	hash.Write(payload)
	return hash.Sum(nil)
}

func policyIdentifier(value *cborValue, maximum int) error {
	text, err := textValue(value)
	if err != nil || len(text) == 0 || len(text) > maximum {
		return errors.New("invalid policy identifier")
	}
	for index := 0; index < len(text); index++ {
		character := text[index]
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '.' || character == '/' ||
			character == ':' || character == '_' || character == '-') {
			return errors.New("invalid policy identifier")
		}
	}
	return nil
}

// decodeBoundedPolicy returns errBoundedPolicyLimit for a size bound and
// another error for any other invalid extension bytes.
func decodeBoundedPolicy(data []byte) (boundedPolicy, error) {
	if len(data) > maxExtensionBytes {
		return boundedPolicy{}, errBoundedPolicyLimit
	}
	root, err := decodeValue(data)
	if err != nil {
		return boundedPolicy{}, err
	}
	if err := exactMap(root, 3); err != nil {
		return boundedPolicy{}, err
	}
	commitment := mustMap(root, 0)
	if err := exactMap(commitment, 5); err != nil {
		return boundedPolicy{}, err
	}
	if err := policyIdentifier(mustMap(commitment, 0), maxPolicyIdentifierBytes); err != nil {
		return boundedPolicy{}, err
	}
	version, err := uintValue(mustMap(commitment, 1))
	if err != nil || version == 0 || version > 0xffff {
		return boundedPolicy{}, errors.New("invalid policy version")
	}
	if err := policyIdentifier(mustMap(commitment, 2), maxPolicyCanonicalizationSize); err != nil {
		return boundedPolicy{}, err
	}
	digest, err := bytesValue(mustMap(commitment, 3), 32)
	if err != nil {
		return boundedPolicy{}, err
	}
	if err := policyIdentifier(mustMap(commitment, 4), maxPolicyIdentifierBytes); err != nil {
		return boundedPolicy{}, err
	}
	policy, err := bytesValue(mustMap(root, 1), -1)
	if err != nil {
		return boundedPolicy{}, err
	}
	if len(policy) > maxBoundedPolicyBytes {
		return boundedPolicy{}, errBoundedPolicyLimit
	}
	if len(policy) == 0 {
		return boundedPolicy{}, errors.New("empty policy")
	}
	parent, err := optionalBytes(mustMap(root, 2))
	if err != nil {
		return boundedPolicy{}, err
	}
	if !bytes.Equal(domainCommitment(boundedPolicyDigestDomain, policy), digest) {
		return boundedPolicy{}, errors.New("policy bytes do not open the commitment")
	}
	return boundedPolicy{parent: parent}, nil
}

func evaluateBoundedPolicyExtension(extension criticalExtension) error {
	if _, err := decodeBoundedPolicy(extension.bytes); err != nil {
		if errors.Is(err, errBoundedPolicyLimit) {
			return denied("resource-limit-exceeded")
		}
		return denied("local-policy-denied")
	}
	return nil
}

// boundedPolicyLaw keeps a bound only when the child links the digest of the
// parent's exact extension bytes, and adds one to an unbounded parent only
// without a link.
func boundedPolicyLaw(child, parent *criticalExtension) bool {
	decoded, err := decodeBoundedPolicy(child.bytes)
	if err != nil {
		return false
	}
	if parent == nil {
		return decoded.parent == nil
	}
	if _, err := decodeBoundedPolicy(parent.bytes); err != nil {
		return false
	}
	return decoded.parent != nil &&
		bytes.Equal(decoded.parent, domainCommitment(boundedPolicyLinkDomain, parent.bytes))
}
