// auths-corpus-check is an independent bounded deterministic-CBOR corpus
// auditor. It deliberately contains no Rust bridge or generated decoder.
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
	"unicode/utf8"
)

const (
	maxBytes = 16 * 1024 * 1024
	maxDepth = 64
	maxItems = 1_000_000
)

type artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	// Encoding is absent or "canonical" for bytes that are the canonical
	// encoding of their object, and "raw" for bytes carried as they are. Only
	// the canonical action may be raw.
	Encoding        string          `json:"encoding"`
	Profile         string          `json:"profile"`
	ProfileVersion  uint64          `json:"profile_version"`
	MediaType       string          `json:"media_type"`
	Capability      string          `json:"capability"`
	Resource        string          `json:"resource"`
	RequestedBudget *manifestBudget `json:"requested_budget"`
}

type manifestBudget struct {
	Algebra string `json:"algebra"`
	Value   uint64 `json:"value"`
}

// expectedResult is a fixture's expected portable result. A null or absent
// plan digest means the result carries none.
type expectedResult struct {
	Path          string  `json:"path"`
	SHA256        string  `json:"sha256"`
	Stage         string  `json:"stage"`
	ProofDigest   string  `json:"proof_digest"`
	ActionDigest  string  `json:"action_digest"`
	ContextDigest string  `json:"context_digest"`
	PlanDigest    *string `json:"plan_digest"`
}

type fixture struct {
	Name             string         `json:"name"`
	Proof            artifact       `json:"proof"`
	Context          artifact       `json:"context"`
	CanonicalAction  artifact       `json:"canonical_action"`
	CanonicalBody    artifact       `json:"canonical_body"`
	ExpectedResult   expectedResult `json:"expected_result"`
	ExpectedDecision string         `json:"expected_decision"`
	ExpectedCode     string         `json:"expected_code"`
}

type manifest struct {
	ProtocolMajor  int            `json:"protocol_major"`
	AdapterContext adapterContext `json:"adapter_context"`
	Fixtures       []fixture      `json:"fixtures"`
}

// rawAction reports whether the fixture's canonical action is carried as raw
// bytes. Any other encoding marker, or a raw marker on another input, is an
// error.
func (value fixture) rawAction() (bool, error) {
	for _, entry := range []artifact{value.Proof, value.Context, value.CanonicalBody} {
		if entry.Encoding != "" && entry.Encoding != "canonical" {
			return false, fmt.Errorf("%s: unsupported encoding %q", entry.Path, entry.Encoding)
		}
	}
	switch value.CanonicalAction.Encoding {
	case "", "canonical":
		return false, nil
	case "raw":
		return true, nil
	default:
		return false, fmt.Errorf(
			"%s: unsupported encoding %q", value.CanonicalAction.Path, value.CanonicalAction.Encoding,
		)
	}
}

type parser struct {
	data  []byte
	at    int
	items int
}

func readManifest(manifestPath string) (manifest, error) {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return manifest{}, err
	}
	var input manifest
	if err := json.Unmarshal(raw, &input); err != nil {
		return manifest{}, err
	}
	if input.ProtocolMajor != 1 || len(input.Fixtures) == 0 {
		return manifest{}, errors.New("unsupported or empty Auths corpus")
	}
	return input, nil
}

// AuditSemantic independently evaluates every fixture of the corpus through
// the per-input verifier and compares each result's decision, code, stage,
// and digests with the manifest. It checks every fixture before failing; the
// error lists each mismatching vector and field. When reportPath is not
// empty, it writes the per-vector report there whether or not any vector
// mismatches. On success it returns the aggregate semantic digest.
func AuditSemantic(manifestPath string, reportPath string) (string, error) {
	input, err := readManifest(manifestPath)
	if err != nil {
		return "", err
	}
	return semanticAudit(input, filepath.Dir(manifestPath), reportPath)
}

// AuditCorpus validates the language-neutral corpus and returns its stable
// inventory digest.
func AuditCorpus(manifestPath string) (string, error) {
	input, err := readManifest(manifestPath)
	if err != nil {
		return "", err
	}
	root := filepath.Dir(manifestPath)
	summary := sha256.New()
	count := 0
	for _, fixture := range input.Fixtures {
		if fixture.Name == "" || fixture.ExpectedCode == "" {
			return "", errors.New("manifest fixture is incomplete")
		}
		raw, err := fixture.rawAction()
		if err != nil {
			return "", err
		}
		if raw && fixture.ExpectedResult.Stage != stageDecode {
			return "", fmt.Errorf(
				"%s: a raw canonical action requires stage %s, not %q",
				fixture.Name, stageDecode, fixture.ExpectedResult.Stage,
			)
		}
		contents := make([][]byte, 0, 5)
		for index, value := range []artifact{
			fixture.Proof,
			fixture.Context,
			fixture.CanonicalAction,
			fixture.CanonicalBody,
			{Path: fixture.ExpectedResult.Path, SHA256: fixture.ExpectedResult.SHA256},
		} {
			if value.Path == "" || value.SHA256 == "" {
				return "", errors.New("manifest artifact is incomplete")
			}
			body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(value.Path)))
			if err != nil {
				return "", err
			}
			if len(body) == 0 || len(body) > maxBytes {
				return "", fmt.Errorf("%s exceeds corpus byte bounds", value.Path)
			}
			digest := sha256.Sum256(body)
			if hex.EncodeToString(digest[:]) != value.SHA256 {
				return "", fmt.Errorf("%s digest mismatch", value.Path)
			}
			// The canonical body remains profile-owned opaque bytes, and a raw
			// action need not be CBOR. Every other protocol input and expected
			// output is deterministic CBOR.
			if index != 3 && !(index == 2 && raw) {
				decoded := parser{data: body}
				_, parseErr := decoded.item(1)
				if parseErr == nil && decoded.at != len(body) {
					parseErr = errors.New("trailing CBOR bytes")
				}
				// A vector whose fault is in raw action bytes carries a proof
				// that parses, whatever its expected code.
				expectMalformedProof := index == 0 && !raw &&
					(fixture.ExpectedCode == "malformed-proof" ||
						fixture.ExpectedCode == "non-canonical-proof")
				if expectMalformedProof && parseErr == nil {
					return "", fmt.Errorf(
						"%s should be rejected as %s",
						value.Path,
						fixture.ExpectedCode,
					)
				}
				if !expectMalformedProof && parseErr != nil {
					return "", fmt.Errorf("%s: %w", value.Path, parseErr)
				}
			}
			summary.Write([]byte(value.Path))
			summary.Write([]byte{0})
			summary.Write(digest[:])
			count++
			contents = append(contents, body)
		}
		// Only a canonical action is compared with the body it carries.
		if !raw {
			action, err := decodeCanonicalAction(contents[2])
			if err != nil {
				return "", fmt.Errorf("%s: %w", fixture.CanonicalAction.Path, err)
			}
			if !bytes.Equal(action.body, contents[3]) {
				return "", fmt.Errorf("%s canonical action/body mismatch", fixture.Name)
			}
		}
	}
	return fmt.Sprintf("%d:%x", count, summary.Sum(nil)), nil
}

// decodeCanonicalAction structurally decodes a corpus action artifact so the
// wire audit can compare its body with the corpus body artifact. Verdicts
// never use it: the verifier decodes actions with decodeBoundedCanonicalAction.
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

func (p *parser) item(depth int) ([]byte, error) {
	if depth > maxDepth || p.items >= maxItems || p.at >= len(p.data) {
		return nil, errors.New("CBOR resource limit or truncation")
	}
	p.items++
	start := p.at
	initial := p.data[p.at]
	p.at++
	major, additional := initial>>5, initial&31
	value, err := p.argument(additional)
	if err != nil {
		return nil, err
	}
	switch major {
	case 0, 1:
	case 2, 3:
		length, err := boundedLength(value, len(p.data)-p.at)
		if err != nil {
			return nil, err
		}
		if major == 3 && !utf8.Valid(p.data[p.at:p.at+length]) {
			return nil, errors.New("invalid CBOR UTF-8")
		}
		p.at += length
	case 4:
		length, err := boundedLength(value, maxItems-p.items)
		if err != nil {
			return nil, err
		}
		for range length {
			if _, err := p.item(depth + 1); err != nil {
				return nil, err
			}
		}
	case 5:
		length, err := boundedLength(value, (maxItems-p.items)/2)
		if err != nil {
			return nil, err
		}
		var previous []byte
		for range length {
			key, err := p.item(depth + 1)
			if err != nil {
				return nil, err
			}
			if previous != nil && canonicalCompare(previous, key) >= 0 {
				return nil, errors.New("duplicate or non-canonical CBOR map key")
			}
			previous = append(previous[:0], key...)
			if _, err := p.item(depth + 1); err != nil {
				return nil, err
			}
		}
	case 7:
		if additional != 20 && additional != 21 && additional != 22 {
			return nil, errors.New("unsupported CBOR simple or floating value")
		}
	default:
		return nil, errors.New("CBOR tags are not admitted")
	}
	return p.data[start:p.at], nil
}

func (p *parser) argument(additional byte) (uint64, error) {
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

func boundedLength(value uint64, maximum int) (int, error) {
	if value > uint64(maximum) {
		return 0, errors.New("CBOR length exceeds bound")
	}
	return int(value), nil
}

func canonicalCompare(left, right []byte) int {
	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	return bytes.Compare(left, right)
}
