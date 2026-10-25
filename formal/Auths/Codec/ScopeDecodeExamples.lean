import Auths.Codec.ScopeConstructor
import Auths.Codec.Evaluation
import qualification.aeneas.generated.scope_codec.Funs
open Aeneas Aeneas.Std Result
set_option maxRecDepth 4096
set_option maxHeartbeats 2000000
namespace Auths.ScopeConstructor.DecodeExamples
open AuthsScopeCodec

def own : cbor.Decoder := ⟨⟨[161#u8, 0#u8, 0#u8], by scalar_tac⟩, 0#usize⟩
def anyAnchor : cbor.Decoder := ⟨⟨[161#u8, 0#u8, 2#u8], by scalar_tac⟩, 0#usize⟩
def unknown : cbor.Decoder := ⟨⟨[161#u8, 0#u8, 3#u8], by scalar_tac⟩, 0#usize⟩
def truncated : cbor.Decoder := ⟨⟨[161#u8, 0#u8], by scalar_tac⟩, 0#usize⟩

theorem accepts_own (limits : auths_model.VerifierLimits) :
    decode.status_scope own limits = ok (.Ok .OwnAnchor, {own with position := 3#usize}) := by
  cbv

theorem accepts_any (limits : auths_model.VerifierLimits) :
    decode.status_scope anyAnchor limits = ok (.Ok .AnyAnchor, {anyAnchor with position := 3#usize}) := by
  cbv

theorem refuses_unknown_tag (limits : auths_model.VerifierLimits) :
    decode.status_scope unknown limits = ok (.Err .Malformed, {unknown with position := 3#usize}) := by
  cbv

theorem refuses_truncation (limits : auths_model.VerifierLimits) :
    decode.status_scope truncated limits = ok (.Err .Malformed, {truncated with position := 2#usize}) := by
  cbv

attribute [local cbv_eval] decode.status_scope_loop.eq_def
  auths_model.StatusScopeAnchors.new_loop.eq_def
  auths_model.identifier.contains_forbidden_identifier_loop.eq_def

def listed : cbor.Decoder := ⟨⟨[162#u8, 0#u8, 1#u8, 1#u8, 129#u8, 104#u8,
  97#u8, 110#u8, 99#u8, 104#u8, 111#u8, 114#u8, 58#u8, 97#u8], by scalar_tac⟩, 0#usize⟩
def emptyListed : cbor.Decoder := ⟨⟨[162#u8, 0#u8, 1#u8, 1#u8, 128#u8], by scalar_tac⟩, 0#usize⟩
def invalidId : cbor.Decoder := ⟨⟨[162#u8, 0#u8, 1#u8, 1#u8, 129#u8, 96#u8], by scalar_tac⟩, 0#usize⟩

def limits : auths_model.VerifierLimits := {
  bundle_bytes := 1#usize
  action_bytes := 1#usize
  context_bytes := 1#usize
  grants := 1#usize
  actions := 1#usize
  plan_leaves := 1#usize
  plan_depth := 1#usize
  plan_branching := 1#usize
  evidence := 1#usize
  evidence_bytes := 1#usize
  bindings := 1#usize
  principal_status := 1#usize
  grant_status := 1#usize
  attachments := 1#usize
  attachment_bytes := 1#usize
  signatures := 1#usize
  signature_bytes := 1#usize
  permissions := 1#usize
  audiences := 1#usize
  extensions := 1#usize
  extension_bytes := 1#usize
  body_digests := 1#usize
  binding_evidence := 1#usize
  canonical_body_bytes := 1#usize
  registry_entries := 1#usize
  trust_anchors := 1024#usize
  work_units := 1#u64
  approvals := 1#usize
  approver_anchors := 1#usize
  approval_requirements := 1#usize
}

theorem accepts_listed : decode.status_scope listed limits =
    ok (.Ok (.Anchors ⟨["anchor:a"], by scalar_tac⟩), {listed with position := 14#usize}) := by
  cbv

theorem refuses_empty_list : decode.status_scope emptyListed limits =
    ok (.Err (.Model .InvalidStatusSnapshot), {emptyListed with position := 5#usize}) := by
  cbv

theorem refuses_invalid_id : decode.status_scope invalidId limits =
    ok (.Err (.Model .InvalidRegistryId), {invalidId with position := 6#usize}) := by
  cbv

theorem refuses_collection_limit : decode.status_scope listed {limits with trust_anchors := 0#usize} =
    ok (.Err .LimitExceeded, {listed with position := 5#usize}) := by
  cbv


def unsortedListed : cbor.Decoder := ⟨⟨[162#u8, 0#u8, 1#u8, 1#u8, 130#u8,
  97#u8, 99#u8, 97#u8, 97#u8], by scalar_tac⟩, 0#usize⟩
def duplicateListed : cbor.Decoder := ⟨⟨[162#u8, 0#u8, 1#u8, 1#u8, 130#u8,
  97#u8, 97#u8, 97#u8, 97#u8], by scalar_tac⟩, 0#usize⟩

/-- This internal field decoder sorts the list. Its caller remains responsible
    for comparing re-encoded bytes before canonical object acceptance. -/
theorem sorts_unsorted_list : decode.status_scope unsortedListed limits =
    ok (.Ok (.Anchors ⟨["a", "c"], by scalar_tac⟩),
      {unsortedListed with position := 9#usize}) := by
  simp only [decode.status_scope, Auths.ScopeConstructor.constructor_refines]
  cbv

theorem refuses_duplicate_list : decode.status_scope duplicateListed limits =
    ok (.Err (.Model .InvalidStatusSnapshot), {duplicateListed with position := 9#usize}) := by
  simp only [decode.status_scope, Auths.ScopeConstructor.constructor_refines]
  cbv

end Auths.ScopeConstructor.DecodeExamples
