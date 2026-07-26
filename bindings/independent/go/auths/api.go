package auths

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Decision is the stable three-way Auths verdict class.
type Decision string

const (
	// Authorized means the proof establishes exact authority.
	Authorized Decision = "authorized"
	// Denied means trustworthy available facts establish rejection.
	Denied Decision = "denied"
	// Indeterminate means a trustworthy fact or capability is unavailable.
	Indeterminate Decision = "indeterminate"
)

// Result is the idiomatic pure-Go verification result.
type Result struct {
	Decision           Decision
	Code               string
	Action             *VerifiedAction
	ProofDigest        []byte
	ContextDigest      []byte
	ActionDigest       []byte
	PlanID             []byte
	ActionIDs          [][]byte
	AuthorizedBranches [][]byte
	Assurance          []ParticipantAssurance
}

// VerifiedAction contains canonical bytes released only after exact authority
// is established. Its contents cannot be constructed by another package.
type VerifiedAction struct {
	canonical []byte
}

// CanonicalBytes returns an immutable copy for a profile's verified decoder.
func (action *VerifiedAction) CanonicalBytes() []byte {
	if action == nil {
		return nil
	}
	return cloneBytes(action.canonical)
}

// ParticipantAssurance is one role-indexed control-evidence report.
type ParticipantAssurance struct {
	Principal string
	Role      uint64
	Adapter   string
	Claims    []AssuranceClaim
}

// AssuranceClaim is one stable claim established by consumed evidence.
type AssuranceClaim struct {
	Kind       string
	ObservedAt *uint64
}

// Explanation is a non-sensitive stable operator diagnostic.
type Explanation struct {
	Code      string
	Message   string
	Retryable bool
}

// Explanation returns a stable native diagnostic.
func (result Result) Explanation() Explanation {
	message := "the supplied proof does not authorize this exact action"
	retryable := result.Decision == Indeterminate
	if result.Decision == Authorized {
		message = "the proof establishes exact authority for this action"
	}
	if retryable {
		message = "a required trustworthy fact or implementation is unavailable"
	}
	return Explanation{Code: result.Code, Message: message, Retryable: retryable}
}

// Engine is a pure-Go verifier with explicit immutable adapter trust.
type Engine struct {
	adapters adapterContext
}

// Verify executes the self-contained pure-Go V1 verifier with the portable
// three-input boundary. It performs no I/O and uses no ambient configuration.
func Verify(
	proofCBOR []byte,
	canonicalActionCBOR []byte,
	trustedContextCBOR []byte,
) Result {
	return (&Engine{}).Verify(proofCBOR, canonicalActionCBOR, trustedContextCBOR)
}

// NewEngine parses the exact adapter-context JSON published with a corpus or
// deployment configuration. Empty bytes select only self-contained methods.
func NewEngine(adapterContextJSON []byte) (*Engine, error) {
	if len(adapterContextJSON) == 0 {
		return &Engine{}, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(adapterContextJSON))
	decoder.DisallowUnknownFields()
	var context adapterContext
	if err := decoder.Decode(&context); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("trailing adapter context")
	}
	return &Engine{adapters: context}, nil
}

// Verify executes the independent bounded V1 verifier without I/O.
func (engine *Engine) Verify(
	proofCBOR []byte,
	canonicalActionCBOR []byte,
	trustedContextCBOR []byte,
) Result {
	action, err := decodeCanonicalAction(canonicalActionCBOR)
	if err != nil {
		return Result{Decision: Denied, Code: "malformed-proof"}
	}
	semantic := verifySemantic(
		"",
		proofCBOR,
		trustedContextCBOR,
		canonicalActionCBOR,
		*action,
		engine.adapters,
	)
	result := Result{
		Decision:           Decision(semantic.decision),
		Code:               semantic.code,
		ProofDigest:        cloneBytes(semantic.proof),
		ContextDigest:      cloneBytes(semantic.context),
		ActionDigest:       cloneBytes(semantic.action),
		PlanID:             cloneBytes(semantic.plan),
		ActionIDs:          cloneByteSlices(semantic.actionIDs),
		AuthorizedBranches: cloneByteSlices(semantic.branches),
	}
	if result.Decision == Authorized {
		result.Action = &VerifiedAction{canonical: cloneBytes(canonicalActionCBOR)}
	}
	for _, report := range semantic.assurance {
		converted := ParticipantAssurance{
			Principal: report.principal,
			Role:      report.role,
			Adapter:   report.adapter,
		}
		for _, claim := range report.claims {
			converted.Claims = append(converted.Claims, AssuranceClaim{
				Kind:       claim.kind,
				ObservedAt: claim.observedAt,
			})
		}
		result.Assurance = append(result.Assurance, converted)
	}
	return result
}

func cloneBytes(value []byte) []byte {
	return append([]byte(nil), value...)
}

func cloneByteSlices(values [][]byte) [][]byte {
	result := make([][]byte, 0, len(values))
	for _, value := range values {
		result = append(result, cloneBytes(value))
	}
	return result
}
