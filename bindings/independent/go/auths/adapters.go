package auths

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type didWebStatementContext struct {
	SigningPreimageDigest string `json:"signing_preimage_digest"`
	ExistedAt             uint64 `json:"existed_at"`
}

type didWebContext struct {
	Kind           string                  `json:"kind"`
	Principal      string                  `json:"principal"`
	DocumentDigest string                  `json:"document_digest"`
	ObservedAt     uint64                  `json:"observed_at"`
	ValidFrom      uint64                  `json:"valid_from"`
	ValidUntil     uint64                  `json:"valid_until"`
	Statement      *didWebStatementContext `json:"statement"`
}

type counterContext struct {
	Kind  string `json:"kind"`
	Value uint32 `json:"value"`
}

type webauthnContext struct {
	CredentialID            string         `json:"credential_id"`
	Principal               string         `json:"principal"`
	VerificationMethod      string         `json:"verification_method"`
	PublicKey               string         `json:"public_key"`
	RPID                    string         `json:"rp_id"`
	Origins                 []string       `json:"origins"`
	RequireUserVerification bool           `json:"require_user_verification"`
	CounterPolicy           counterContext `json:"counter_policy"`
	AttestationLevel        *string        `json:"attestation_level"`
	ObservedAt              uint64         `json:"observed_at"`
	ValidUntil              uint64         `json:"valid_until"`
}

type hsmContext struct {
	Principal          string `json:"principal"`
	VerificationMethod string `json:"verification_method"`
	Suite              string `json:"suite"`
	PublicKey          string `json:"public_key"`
	Profile            string `json:"profile"`
	Provider           string `json:"provider"`
	ProtectionLevel    string `json:"protection_level"`
	KeyHandleDigest    string `json:"key_handle_digest"`
	DeviceChainDigest  string `json:"device_chain_digest"`
	NonExportable      bool   `json:"non_exportable"`
	ObservedAt         uint64 `json:"observed_at"`
	ValidUntil         uint64 `json:"valid_until"`
}

type spiffeTrustContext struct {
	Name          string   `json:"name"`
	Roots         []string `json:"roots"`
	RequireStatus bool     `json:"require_status"`
}

type spiffeStatusContext struct {
	LeafDigest string `json:"leaf_digest"`
	Active     bool   `json:"active"`
	ObservedAt uint64 `json:"observed_at"`
	ValidUntil uint64 `json:"valid_until"`
}

type spiffeContext struct {
	TrustDomains []spiffeTrustContext  `json:"trust_domains"`
	Status       []spiffeStatusContext `json:"status"`
}

type adapterContext struct {
	Configuration string            `json:"configuration"`
	DidWeb        []didWebContext   `json:"did_web"`
	WebAuthn      []webauthnContext `json:"webauthn"`
	HSM           []hsmContext      `json:"hsm"`
	Spiffe        spiffeContext     `json:"spiffe"`
}

type assuranceClaim struct {
	kind       string
	observedAt *uint64
}

type controlResult struct {
	key              []byte
	signatureMessage []byte
	claims           []assuranceClaim
	consumed         [][]byte
	adapter          string
	work             uint64
}

type evidenceReader struct {
	body []byte
	at   int
}

func (reader *evidenceReader) take(length int) ([]byte, error) {
	if length < 0 || reader.at+length > len(reader.body) {
		return nil, errors.New("truncated evidence")
	}
	value := reader.body[reader.at : reader.at+length]
	reader.at += length
	return value, nil
}

func (reader *evidenceReader) u8() (byte, error) {
	value, err := reader.take(1)
	if err != nil {
		return 0, err
	}
	return value[0], nil
}

func (reader *evidenceReader) u16() (uint16, error) {
	value, err := reader.take(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(value), nil
}

func (reader *evidenceReader) u32() (uint32, error) {
	value, err := reader.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(value), nil
}

func (reader *evidenceReader) text8() (string, error) {
	length, err := reader.u8()
	if err != nil {
		return "", err
	}
	value, err := reader.take(int(length))
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func selectEvidence(kind, media string, evidence []*evidenceObject) (*evidenceObject, error) {
	var selected *evidenceObject
	for _, object := range evidence {
		if object.kind == kind {
			if selected != nil || object.mediaType != media {
				return nil, denied("principal-method-mismatch")
			}
			selected = object
		}
	}
	if selected == nil {
		return nil, indeterminate("missing-principal-evidence")
	}
	return selected, nil
}

func verifyControl(
	method string,
	principal string,
	descriptor signatureDescriptor,
	purpose uint64,
	signingTime uint64,
	preimage []byte,
	evidence []*evidenceObject,
	context *verifierContext,
	adapters adapterContext,
) (controlResult, error) {
	if !containsText(context.principalMethods, method) {
		return controlResult{}, indeterminate("unsupported-principal-method")
	}
	if !containsText(context.signatureSuites, descriptor.suite) {
		return controlResult{}, indeterminate("unsupported-signature-suite")
	}
	for _, object := range evidence {
		if !containsText(context.evidenceTypes, object.kind) {
			return controlResult{}, indeterminate("unsupported-evidence-type")
		}
	}
	var result controlResult
	var err error
	switch method {
	case "raw-key-v1":
		result, err = rawKeyControl(principal, descriptor, evidence)
	case "did-key-v1":
		result, err = didKeyControl(principal, descriptor, evidence)
	case "did-web-bundled-v1":
		result, err = didWebControl(
			principal, descriptor, purpose, signingTime, preimage, evidence,
			context.evaluationTime, adapters.DidWeb,
		)
	case "did-keri-v1":
		result, err = didKeriControl(principal, descriptor, evidence)
	case "webauthn-v1":
		result, err = webauthnControl(
			principal, descriptor, preimage, evidence, context.evaluationTime, adapters.WebAuthn,
		)
	case "hsm-attested-v1":
		result, err = hsmControl(
			principal, descriptor, preimage, evidence, context.evaluationTime, adapters.HSM,
		)
	case "spiffe-x509-v1":
		result, err = spiffeControl(
			principal, descriptor, evidence, context.evaluationTime, adapters.Spiffe,
		)
	default:
		err = indeterminate("unsupported-principal-method")
	}
	if err != nil {
		return controlResult{}, err
	}
	return result, nil
}

func rawKeyControl(
	principal string,
	descriptor signatureDescriptor,
	evidence []*evidenceObject,
) (controlResult, error) {
	object, err := selectEvidence(
		"raw-key-v1", "application/vnd.auths.raw-key.v1", evidence,
	)
	if err != nil {
		return controlResult{}, err
	}
	domain := []byte("AUTHS-RAW-KEY\x00\x01")
	if !bytes.HasPrefix(object.body, domain) || len(object.body) < len(domain)+3 {
		return controlResult{}, denied("principal-method-mismatch")
	}
	offset := len(domain)
	tag := object.body[offset]
	length := int(binary.BigEndian.Uint16(object.body[offset+1 : offset+3]))
	key := object.body[offset+3:]
	suite := ""
	switch tag {
	case 1:
		suite = "ed25519-v1"
	case 2:
		suite = "p256-sha256-v1"
	default:
		return controlResult{}, denied("principal-method-mismatch")
	}
	if len(key) != length || (tag == 1 && length != 32) || (tag == 2 && length != 33) {
		return controlResult{}, denied("principal-method-mismatch")
	}
	if descriptor.suite != suite {
		return controlResult{}, denied("signature-suite-mismatch")
	}
	digest := sha256.Sum256(object.body)
	expected := "key:sha256:" + base64.RawURLEncoding.EncodeToString(digest[:])
	if principal != expected {
		return controlResult{}, denied("principal-method-mismatch")
	}
	if descriptor.verificationMethod != principal {
		return controlResult{}, denied("verification-method-mismatch")
	}
	return controlResult{
		key:      append([]byte(nil), key...),
		claims:   []assuranceClaim{{kind: "self-certifying-identifier"}, {kind: "offline-verifiable"}},
		consumed: [][]byte{object.id},
		adapter:  "raw-key-v1",
		work:     10,
	}, nil
}

func didKeyControl(
	principal string,
	descriptor signatureDescriptor,
	evidence []*evidenceObject,
) (controlResult, error) {
	object, err := selectEvidence(
		"did-key-v1", "application/vnd.auths.did-key.v1", evidence,
	)
	if err != nil {
		return controlResult{}, err
	}
	reader := evidenceReader{body: object.body}
	domain, err := reader.take(len("AUTHS-DID-KEY\x00\x01"))
	if err != nil || string(domain) != "AUTHS-DID-KEY\x00\x01" {
		return controlResult{}, denied("principal-method-mismatch")
	}
	length, err := reader.u16()
	if err != nil {
		return controlResult{}, denied("principal-method-mismatch")
	}
	encoded, err := reader.take(int(length))
	if err != nil || reader.at != len(reader.body) {
		return controlResult{}, denied("principal-method-mismatch")
	}
	key, suite, err := decodeMultikey(string(encoded))
	if err != nil {
		return controlResult{}, denied("principal-method-mismatch")
	}
	expected := "did:key:" + string(encoded)
	if principal != expected {
		return controlResult{}, denied("principal-method-mismatch")
	}
	if descriptor.verificationMethod != expected+"#"+string(encoded) {
		return controlResult{}, denied("verification-method-mismatch")
	}
	if descriptor.suite != suite {
		return controlResult{}, denied("signature-suite-mismatch")
	}
	return controlResult{
		key:      key,
		claims:   []assuranceClaim{{kind: "self-certifying-identifier"}, {kind: "offline-verifiable"}},
		consumed: [][]byte{object.id},
		adapter:  "did-key-v1",
		work:     20,
	}, nil
}

func decodeMultikey(encoded string) ([]byte, string, error) {
	if !strings.HasPrefix(encoded, "z") {
		return nil, "", errors.New("unsupported multibase")
	}
	decoded, err := base58Decode(encoded[1:])
	if err != nil || len(decoded) < 2 {
		return nil, "", errors.New("invalid multikey")
	}
	switch {
	case decoded[0] == 0xed && decoded[1] == 0x01 && len(decoded) == 34:
		return decoded[2:], "ed25519-v1", nil
	case decoded[0] == 0x80 && decoded[1] == 0x24 && len(decoded) == 35:
		return decoded[2:], "p256-sha256-v1", nil
	default:
		return nil, "", errors.New("unsupported multicodec")
	}
}

func base58Decode(value string) ([]byte, error) {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	number := new(bigInt).zero()
	for _, char := range value {
		index := strings.IndexRune(alphabet, char)
		if index < 0 {
			return nil, errors.New("invalid base58")
		}
		number.multiplyAdd(58, byte(index))
	}
	result := number.bytes()
	for index := 0; index < len(value) && value[index] == '1'; index++ {
		result = append([]byte{0}, result...)
	}
	return result, nil
}

// bigInt is a minimal base-256 integer used only for bounded base58 decoding.
type bigInt struct {
	octets []byte
}

func (value *bigInt) zero() *bigInt {
	value.octets = []byte{0}
	return value
}

func (value *bigInt) multiplyAdd(multiplier int, add byte) {
	carry := int(add)
	for index := len(value.octets) - 1; index >= 0; index-- {
		current := int(value.octets[index])*multiplier + carry
		value.octets[index] = byte(current)
		carry = current >> 8
	}
	for carry > 0 {
		value.octets = append([]byte{byte(carry)}, value.octets...)
		carry >>= 8
	}
}

func (value *bigInt) bytes() []byte {
	index := 0
	for index < len(value.octets)-1 && value.octets[index] == 0 {
		index++
	}
	return append([]byte(nil), value.octets[index:]...)
}

func didWebControl(
	principal string,
	descriptor signatureDescriptor,
	purpose uint64,
	signingTime uint64,
	preimage []byte,
	evidence []*evidenceObject,
	evaluationTime uint64,
	context []didWebContext,
) (controlResult, error) {
	object, err := selectEvidence(
		"did-web-bundled-v1", "application/vnd.auths.did-web-bundle.v1", evidence,
	)
	if err != nil {
		return controlResult{}, err
	}
	reader := evidenceReader{body: object.body}
	domain, err := reader.take(len("AUTHS-DID-WEB\x00\x01"))
	if err != nil || string(domain) != "AUTHS-DID-WEB\x00\x01" {
		return controlResult{}, denied("principal-method-mismatch")
	}
	principalLength, err := reader.u16()
	if err != nil {
		return controlResult{}, denied("principal-method-mismatch")
	}
	evidencePrincipal, err := reader.take(int(principalLength))
	if err != nil || string(evidencePrincipal) != principal {
		return controlResult{}, denied("principal-method-mismatch")
	}
	documentLength, err := reader.u32()
	if err != nil {
		return controlResult{}, denied("principal-method-mismatch")
	}
	document, err := reader.take(int(documentLength))
	if err != nil || reader.at != len(reader.body) {
		return controlResult{}, denied("principal-method-mismatch")
	}
	var didDocument struct {
		ID                 string `json:"id"`
		VerificationMethod []struct {
			ID                 string `json:"id"`
			Type               string `json:"type"`
			Controller         string `json:"controller"`
			PublicKeyMultibase string `json:"publicKeyMultibase"`
		} `json:"verificationMethod"`
		AssertionMethod      []string `json:"assertionMethod"`
		CapabilityDelegation []string `json:"capabilityDelegation"`
		CapabilityInvocation []string `json:"capabilityInvocation"`
	}
	if err := json.Unmarshal(document, &didDocument); err != nil || didDocument.ID != principal {
		return controlResult{}, denied("principal-method-mismatch")
	}
	relationship := didDocument.AssertionMethod
	if purpose == 0 {
		relationship = didDocument.CapabilityDelegation
	} else if purpose == 1 {
		relationship = didDocument.CapabilityInvocation
	}
	if !containsText(relationship, descriptor.verificationMethod) {
		return controlResult{}, denied("verification-method-mismatch")
	}
	var key []byte
	suite := ""
	for _, method := range didDocument.VerificationMethod {
		if method.ID == descriptor.verificationMethod &&
			method.Type == "Multikey" && method.Controller == principal {
			key, suite, err = decodeMultikey(method.PublicKeyMultibase)
			break
		}
	}
	if err != nil || key == nil {
		return controlResult{}, denied("verification-method-mismatch")
	}
	if descriptor.suite != suite {
		return controlResult{}, denied("signature-suite-mismatch")
	}
	documentDigest := sha256.Sum256(document)
	claims := make([]assuranceClaim, 0, 4)
	trusted := false
	matchingDocument := false
	for _, record := range context {
		expected, decodeErr := hex.DecodeString(record.DocumentDigest)
		if decodeErr != nil || record.Principal != principal || !bytes.Equal(expected, documentDigest[:]) {
			continue
		}
		matchingDocument = true
		switch record.Kind {
		case "current":
			if record.ObservedAt <= evaluationTime && evaluationTime <= record.ValidUntil {
				observed := record.ObservedAt
				claims = append(claims,
					assuranceClaim{kind: "controller-state-current-at", observedAt: &observed},
					assuranceClaim{kind: "revocation-checked-at", observedAt: &observed},
				)
				trusted = true
			}
		case "historical":
			if record.ValidFrom <= signingTime && signingTime <= record.ValidUntil {
				observed := signingTime
				claims = append(claims, assuranceClaim{kind: "historical-at", observedAt: &observed})
				trusted = true
				if record.Statement != nil {
					actual := sha256.Sum256(preimage)
					expected, _ := hex.DecodeString(record.Statement.SigningPreimageDigest)
					if bytes.Equal(actual[:], expected) &&
						record.Statement.ExistedAt >= signingTime &&
						record.Statement.ExistedAt <= record.ValidUntil {
						existed := record.Statement.ExistedAt
						claims = append(claims, assuranceClaim{
							kind: "statement-existence-proven-at", observedAt: &existed,
						})
					}
				}
			}
		}
	}
	if !trusted {
		if matchingDocument {
			return controlResult{}, indeterminate("historical-state-unavailable")
		}
		return controlResult{}, indeterminate("external-fact-unavailable")
	}
	claims = append(claims,
		assuranceClaim{kind: "offline-verifiable"},
		assuranceClaim{kind: "rotation-aware"},
	)
	return controlResult{
		key: key, claims: claims, consumed: [][]byte{object.id},
		adapter: "did-web-bundled-v1", work: 45,
	}, nil
}

func didKeriControl(
	principal string,
	descriptor signatureDescriptor,
	evidence []*evidenceObject,
) (controlResult, error) {
	object, err := selectEvidence(
		"did-keri-v1", "application/vnd.auths.did-keri-kel.v1", evidence,
	)
	if err != nil {
		return controlResult{}, err
	}
	reader := evidenceReader{body: object.body}
	domain, err := reader.take(len("AUTHS-DID-KERI\x00\x01"))
	if err != nil || string(domain) != "AUTHS-DID-KERI\x00\x01" {
		return controlResult{}, denied("principal-method-mismatch")
	}
	count, err := reader.u16()
	if err != nil || count == 0 || count > 64 {
		return controlResult{}, denied("principal-method-mismatch")
	}
	var inceptionID string
	var currentKeys []string
	var establishmentSequence uint64
	var nextKeys []any
	for index := 0; index < int(count); index++ {
		eventLength, err := reader.u32()
		if err != nil || eventLength == 0 || eventLength > 64*1024 {
			return controlResult{}, denied("principal-method-mismatch")
		}
		eventBytes, err := reader.take(int(eventLength))
		if err != nil {
			return controlResult{}, denied("principal-method-mismatch")
		}
		attachmentLength, err := reader.u32()
		if err != nil || attachmentLength == 0 || attachmentLength > 16*1024 {
			return controlResult{}, denied("principal-method-mismatch")
		}
		if _, err := reader.take(int(attachmentLength)); err != nil {
			return controlResult{}, denied("principal-method-mismatch")
		}
		var event map[string]any
		if err := json.Unmarshal(eventBytes, &event); err != nil {
			return controlResult{}, denied("principal-method-mismatch")
		}
		eventType, _ := event["t"].(string)
		sequenceText, _ := event["s"].(string)
		sequence, err := strconv.ParseUint(sequenceText, 16, 64)
		if err != nil || sequence != uint64(index) {
			return controlResult{}, denied("principal-method-mismatch")
		}
		if index == 0 {
			inceptionID, _ = event["i"].(string)
			if eventType != "icp" || inceptionID == "" || event["d"] != inceptionID {
				return controlResult{}, denied("principal-method-mismatch")
			}
		}
		if eventType == "icp" || eventType == "rot" {
			keyValues, ok := event["k"].([]any)
			if !ok || len(keyValues) == 0 {
				return controlResult{}, denied("principal-method-mismatch")
			}
			currentKeys = currentKeys[:0]
			for _, value := range keyValues {
				key, ok := value.(string)
				if !ok {
					return controlResult{}, denied("principal-method-mismatch")
				}
				currentKeys = append(currentKeys, key)
			}
			nextKeys, _ = event["n"].([]any)
			establishmentSequence = sequence
		}
	}
	if reader.at != len(reader.body) || principal != "did:keri:"+inceptionID {
		return controlResult{}, denied("principal-method-mismatch")
	}
	expectedPrefix := fmt.Sprintf("%s#key-%x-", principal, establishmentSequence)
	if !strings.HasPrefix(descriptor.verificationMethod, expectedPrefix) {
		return controlResult{}, denied("verification-method-mismatch")
	}
	keyIndex, err := strconv.Atoi(strings.TrimPrefix(descriptor.verificationMethod, expectedPrefix))
	if err != nil || keyIndex < 0 || keyIndex >= len(currentKeys) {
		return controlResult{}, denied("verification-method-mismatch")
	}
	key, suite, err := decodeKeriKey(currentKeys[keyIndex])
	if err != nil {
		return controlResult{}, denied("principal-method-mismatch")
	}
	if descriptor.suite != suite {
		return controlResult{}, denied("signature-suite-mismatch")
	}
	claims := []assuranceClaim{
		{kind: "self-certifying-identifier"},
		{kind: "offline-verifiable"},
	}
	if len(nextKeys) > 0 {
		claims = append(claims, assuranceClaim{kind: "rotation-aware"})
	}
	return controlResult{
		key: key, claims: claims, consumed: [][]byte{object.id},
		adapter: "did-keri-v1", work: 60 + uint64(count)*40,
	}, nil
}

func decodeKeriKey(value string) ([]byte, string, error) {
	if (strings.HasPrefix(value, "D") || strings.HasPrefix(value, "B")) && len(value) == 44 {
		decoded, err := base64.RawURLEncoding.DecodeString("A" + value[1:])
		if err != nil || len(decoded) != 33 || decoded[0] != 0 {
			return nil, "", errors.New("invalid KERI Ed25519 key")
		}
		return decoded[1:], "ed25519-v1", nil
	}
	if (strings.HasPrefix(value, "1AAJ") || strings.HasPrefix(value, "1AAI")) && len(value) == 48 {
		decoded, err := base64.RawURLEncoding.DecodeString(value[4:])
		if err != nil || len(decoded) != 33 {
			return nil, "", errors.New("invalid KERI P-256 key")
		}
		return decoded, "p256-sha256-v1", nil
	}
	return nil, "", errors.New("unsupported KERI key")
}

func webauthnControl(
	principal string,
	descriptor signatureDescriptor,
	preimage []byte,
	evidence []*evidenceObject,
	evaluationTime uint64,
	context []webauthnContext,
) (controlResult, error) {
	if descriptor.suite != "p256-sha256-v1" {
		return controlResult{}, denied("signature-suite-mismatch")
	}
	var credential *webauthnContext
	for index := range context {
		if context[index].Principal == principal {
			credential = &context[index]
			break
		}
	}
	if credential == nil {
		return controlResult{}, indeterminate("external-fact-unavailable")
	}
	if descriptor.verificationMethod != credential.VerificationMethod {
		return controlResult{}, denied("verification-method-mismatch")
	}
	if evaluationTime < credential.ObservedAt || evaluationTime > credential.ValidUntil {
		return controlResult{}, indeterminate("external-fact-unavailable")
	}
	object, err := selectEvidence(
		"webauthn-v1", "application/vnd.auths.webauthn-assertion.v1", evidence,
	)
	if err != nil {
		return controlResult{}, err
	}
	reader := evidenceReader{body: object.body}
	domain, err := reader.take(len("AUTHS-WEBAUTHN\x00\x01"))
	if err != nil || string(domain) != "AUTHS-WEBAUTHN\x00\x01" {
		return controlResult{}, denied("principal-method-mismatch")
	}
	credentialLength, err := reader.u16()
	if err != nil {
		return controlResult{}, denied("principal-method-mismatch")
	}
	credentialID, err := reader.take(int(credentialLength))
	if err != nil {
		return controlResult{}, denied("principal-method-mismatch")
	}
	expectedCredential, _ := hex.DecodeString(credential.CredentialID)
	if !bytes.Equal(credentialID, expectedCredential) {
		return controlResult{}, denied("principal-method-mismatch")
	}
	authenticatorLength, err := reader.u16()
	if err != nil {
		return controlResult{}, denied("principal-method-mismatch")
	}
	authenticator, err := reader.take(int(authenticatorLength))
	if err != nil || len(authenticator) < 37 {
		return controlResult{}, denied("principal-method-mismatch")
	}
	clientLength, err := reader.u32()
	if err != nil {
		return controlResult{}, denied("principal-method-mismatch")
	}
	clientData, err := reader.take(int(clientLength))
	if err != nil || reader.at != len(reader.body) {
		return controlResult{}, denied("principal-method-mismatch")
	}
	rpDigest := sha256.Sum256([]byte(credential.RPID))
	flags := authenticator[32]
	if !bytes.Equal(authenticator[:32], rpDigest[:]) ||
		flags&1 == 0 || (credential.RequireUserVerification && flags&4 == 0) {
		return controlResult{}, denied("principal-method-mismatch")
	}
	counter := binary.BigEndian.Uint32(authenticator[33:37])
	if credential.CounterPolicy.Kind == "greater-than" &&
		(counter == 0 || counter <= credential.CounterPolicy.Value) {
		return controlResult{}, denied("principal-method-mismatch")
	}
	client, err := jsonObject(clientData)
	if err != nil {
		return controlResult{}, denied("principal-method-mismatch")
	}
	clientType, _ := stringField(client, "type")
	challenge, challengeErr := stringField(client, "challenge")
	origin, originErr := stringField(client, "origin")
	decodedChallenge, decodeErr := decodeBase64URL(challenge)
	expectedChallenge := sha256.Sum256(preimage)
	if clientType != "webauthn.get" || challengeErr != nil || originErr != nil ||
		decodeErr != nil || !bytes.Equal(decodedChallenge, expectedChallenge[:]) ||
		!containsText(credential.Origins, origin) {
		return controlResult{}, denied("principal-method-mismatch")
	}
	claims := []assuranceClaim{
		{kind: "origin-bound", observedAt: &credential.ObservedAt},
		{kind: "controller-state-current-at", observedAt: &credential.ObservedAt},
		{kind: "revocation-checked-at", observedAt: &credential.ObservedAt},
	}
	if flags&4 != 0 {
		now := evaluationTime
		claims = append(claims, assuranceClaim{kind: "user-verified", observedAt: &now})
	}
	if credential.AttestationLevel != nil {
		claims = append(claims, assuranceClaim{
			kind: "hardware-attested", observedAt: &credential.ObservedAt,
		})
	}
	clientDigest := sha256.Sum256(clientData)
	message := append(append([]byte(nil), authenticator...), clientDigest[:]...)
	key, err := hex.DecodeString(credential.PublicKey)
	if err != nil {
		return controlResult{}, indeterminate("external-fact-unavailable")
	}
	return controlResult{
		key: key, signatureMessage: message, claims: claims,
		consumed: [][]byte{object.id}, adapter: "webauthn-v1", work: 75,
	}, nil
}

func hsmControl(
	principal string,
	descriptor signatureDescriptor,
	preimage []byte,
	evidence []*evidenceObject,
	evaluationTime uint64,
	context []hsmContext,
) (controlResult, error) {
	var record *hsmContext
	for index := range context {
		if context[index].Principal == principal {
			record = &context[index]
			break
		}
	}
	if record == nil {
		return controlResult{}, indeterminate("external-fact-unavailable")
	}
	if descriptor.verificationMethod != record.VerificationMethod {
		return controlResult{}, denied("verification-method-mismatch")
	}
	if descriptor.suite != record.Suite {
		return controlResult{}, denied("signature-suite-mismatch")
	}
	if evaluationTime < record.ObservedAt || evaluationTime > record.ValidUntil {
		return controlResult{}, indeterminate("external-fact-unavailable")
	}
	object, err := selectEvidence(
		"hsm-attested-v1", "application/vnd.auths.hsm-attested.v1", evidence,
	)
	if err != nil {
		return controlResult{}, err
	}
	reader := evidenceReader{body: object.body}
	domain, err := reader.take(len("AUTHS-HSM-ATTESTED\x00\x01"))
	if err != nil || string(domain) != "AUTHS-HSM-ATTESTED\x00\x01" {
		return controlResult{}, denied("principal-method-mismatch")
	}
	profile, profileErr := reader.text8()
	provider, providerErr := reader.text8()
	level, levelErr := reader.text8()
	handle, handleErr := reader.take(32)
	device, deviceErr := reader.take(32)
	nonExportable, exportErr := reader.u8()
	transaction, transactionErr := reader.take(32)
	expectedHandle, _ := hex.DecodeString(record.KeyHandleDigest)
	expectedDevice, _ := hex.DecodeString(record.DeviceChainDigest)
	expectedTransaction := sha256.Sum256(preimage)
	if profileErr != nil || providerErr != nil || levelErr != nil || handleErr != nil ||
		deviceErr != nil || exportErr != nil || transactionErr != nil ||
		reader.at != len(reader.body) || profile != record.Profile ||
		provider != record.Provider || level != record.ProtectionLevel ||
		!bytes.Equal(handle, expectedHandle) || !bytes.Equal(device, expectedDevice) ||
		(nonExportable == 1) != record.NonExportable ||
		!bytes.Equal(transaction, expectedTransaction[:]) {
		return controlResult{}, denied("principal-method-mismatch")
	}
	key, err := hex.DecodeString(record.PublicKey)
	if err != nil {
		return controlResult{}, indeterminate("external-fact-unavailable")
	}
	return controlResult{
		key: key,
		claims: []assuranceClaim{
			{kind: "hardware-attested", observedAt: &record.ObservedAt},
			{kind: "controller-state-current-at", observedAt: &record.ObservedAt},
			{kind: "revocation-checked-at", observedAt: &record.ObservedAt},
			{kind: "offline-verifiable"},
		},
		consumed: [][]byte{object.id}, adapter: "hsm-attested-v1", work: 55,
	}, nil
}

func spiffeControl(
	principal string,
	descriptor signatureDescriptor,
	evidence []*evidenceObject,
	evaluationTime uint64,
	context spiffeContext,
) (controlResult, error) {
	parsedURI, err := url.Parse(principal)
	if err != nil || parsedURI.Scheme != "spiffe" || parsedURI.Host == "" {
		return controlResult{}, denied("principal-method-mismatch")
	}
	var trust *spiffeTrustContext
	for index := range context.TrustDomains {
		if context.TrustDomains[index].Name == parsedURI.Host {
			trust = &context.TrustDomains[index]
			break
		}
	}
	if trust == nil {
		return controlResult{}, indeterminate("external-fact-unavailable")
	}
	object, err := selectEvidence(
		"spiffe-x509-v1", "application/vnd.auths.spiffe-x509-svid.v1", evidence,
	)
	if err != nil {
		return controlResult{}, err
	}
	reader := evidenceReader{body: object.body}
	domain, err := reader.take(len("AUTHS-SPIFFE-X509\x00\x01"))
	if err != nil || string(domain) != "AUTHS-SPIFFE-X509\x00\x01" {
		return controlResult{}, denied("principal-method-mismatch")
	}
	count, err := reader.u16()
	if err != nil || count == 0 || count > 8 {
		return controlResult{}, denied("principal-method-mismatch")
	}
	certificates := make([]*x509.Certificate, 0, count)
	var leafDER []byte
	for index := 0; index < int(count); index++ {
		length, err := reader.u32()
		if err != nil {
			return controlResult{}, denied("principal-method-mismatch")
		}
		der, err := reader.take(int(length))
		if err != nil {
			return controlResult{}, denied("principal-method-mismatch")
		}
		if index == 0 {
			leafDER = append([]byte(nil), der...)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return controlResult{}, denied("principal-method-mismatch")
		}
		certificates = append(certificates, certificate)
	}
	if reader.at != len(reader.body) {
		return controlResult{}, denied("principal-method-mismatch")
	}
	roots := x509.NewCertPool()
	for _, encoded := range trust.Roots {
		der, err := hex.DecodeString(encoded)
		if err != nil {
			return controlResult{}, indeterminate("external-fact-unavailable")
		}
		root, err := x509.ParseCertificate(der)
		if err != nil {
			return controlResult{}, indeterminate("external-fact-unavailable")
		}
		roots.AddCert(root)
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	_, err = certificates[0].Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates,
		CurrentTime: time.Unix(int64(evaluationTime), 0).UTC(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return controlResult{}, denied("principal-method-mismatch")
	}
	if len(certificates[0].URIs) != 1 || certificates[0].URIs[0].String() != principal {
		return controlResult{}, denied("principal-method-mismatch")
	}
	key, ok := certificates[0].PublicKey.(ed25519.PublicKey)
	if !ok || descriptor.suite != "ed25519-v1" {
		return controlResult{}, denied("signature-suite-mismatch")
	}
	leafDigest := sha256.Sum256(leafDER)
	encodedLeafDigest := base64.RawURLEncoding.EncodeToString(leafDigest[:])
	expectedMethod := fmt.Sprintf("%s#svid-%s", principal, encodedLeafDigest[:16])
	if descriptor.verificationMethod != expectedMethod {
		return controlResult{}, denied("verification-method-mismatch")
	}
	var status *spiffeStatusContext
	for index := range context.Status {
		expected, _ := hex.DecodeString(context.Status[index].LeafDigest)
		if bytes.Equal(expected, leafDigest[:]) &&
			context.Status[index].ObservedAt <= evaluationTime &&
			evaluationTime <= context.Status[index].ValidUntil {
			status = &context.Status[index]
			break
		}
	}
	if status != nil && !status.Active {
		return controlResult{}, denied("principal-revoked")
	}
	if trust.RequireStatus && status == nil {
		return controlResult{}, indeterminate("external-fact-unavailable")
	}
	now := evaluationTime
	claims := []assuranceClaim{
		{kind: "pki-chain-validated", observedAt: &now},
		{kind: "workload-attested", observedAt: &now},
	}
	if status != nil {
		claims = append(claims,
			assuranceClaim{kind: "controller-state-current-at", observedAt: &status.ObservedAt},
			assuranceClaim{kind: "revocation-checked-at", observedAt: &status.ObservedAt},
		)
	}
	return controlResult{
		key: append([]byte(nil), key...), claims: claims, consumed: [][]byte{object.id},
		adapter: "spiffe-x509-v1", work: 120 + uint64(count)*35,
	}, nil
}
