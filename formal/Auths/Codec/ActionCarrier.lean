import Auths.Codec.AttachmentInverse
import Auths.Codec.AttachmentValidation
import Auths.Codec.ActionResources
import Auths.Codec.Limits
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.ActionCarrier
open ActionDecodedFields AttachmentResources AttachmentSort

/-- Independent constructor-valid carrier relation. Canonical attachment
order and digest uniqueness are semantic list predicates, not successful
constructor, parser, encoder or desired-verdict assumptions. -/
structure Valid (action : auths_codec.auths_model.CanonicalAction) : Prop where
  fields : FieldsValid action
  body_nonempty : 0 < action.body.val.length
  body_bound : action.body.val.length ≤ 8388608
  attachment_count : action.detached_attachments.val.length ≤ 512
  attachment_bytes : byteSum action.detached_attachments.val ≤ 8388608
  attachment_payloads : AttachmentInverse.WellFormed action.detached_attachments.val
  attachment_order : action.detached_attachments.val.Pairwise digestLE
  attachment_unique : (action.detached_attachments.val.map (fun value => value.digest)).Nodup

/-- A deployment may intentionally reject an otherwise valid protocol value.
Completeness therefore quantifies over the exact encoded-byte and structural
limits relevant to this object, as well as the complete valid limit record. -/
structure Fits (limits : auths_codec.auths_model.VerifierLimits)
    (action : auths_codec.auths_model.CanonicalAction) : Prop where
  limits_valid : Limits.Valid limits
  encoded_bytes : (ActionEncode.actionEncoding action).length ≤ limits.action_bytes.val
  body_bytes : action.body.val.length ≤ limits.canonical_body_bytes.val
  attachment_count : action.detached_attachments.val.length ≤ limits.attachments.val
  attachment_bytes : byteSum action.detached_attachments.val ≤ limits.attachment_bytes.val

theorem validFrom_of_unique (values : List auths_codec.auths_model.DetachedAttachment)
    (previous : Option auths_codec.auths_model.AttachmentDigest) (total : Nat)
    (unique : (values.map (fun value => value.digest)).Nodup)
    (previous_absent : ∀ value ∈ values, previous ≠ some value.digest)
    (bounded : total + byteSum values ≤ 8388608) :
    AttachmentValidation.validFrom previous total values = true := by
  induction values generalizing previous total with
  | nil => rfl
  | cons first rest ih =>
    have notPrevious := previous_absent first (by simp)
    have noDuplicates := List.nodup_cons.mp unique
    have restBound : total + first.bytes.val.length + byteSum rest ≤ 8388608 := by
      simpa [byteSum] using bounded
    have firstBound : total + first.bytes.val.length ≤ 8388608 := by omega
    simp only [AttachmentValidation.validFrom, notPrevious, ↓reduceIte, firstBound]
    apply ih (some first.digest) (total + first.bytes.val.length) noDuplicates.2
    · intro value member equal
      have same : first.digest = value.digest := Option.some.inj equal
      apply noDuplicates.1
      exact List.mem_map.mpr ⟨value, member, same.symm⟩
    · exact restBound

theorem normalization_identity (action : auths_codec.auths_model.CanonicalAction)
    (valid : Valid action) :
    auths_model.CanonicalAction.with_detached_attachments
      {action with detached_attachments := alloc.vec.Vec.new _} action.detached_attachments
      ⦃ actual => actual = .Ok action ⦄ := by
  have order : AttachmentSort.sorted action.detached_attachments.val = action.detached_attachments.val :=
    List.Pairwise.insertionSort_eq valid.attachment_order
  have contents : AttachmentValidation.valid action.detached_attachments.val = true :=
    validFrom_of_unique _ none 0 valid.attachment_unique (by simp) (by simpa using valid.attachment_bytes)
  apply spec_mono (AttachmentValidation.constructor_exact
    {action with detached_attachments := alloc.vec.Vec.new _} action.detached_attachments)
  intro actual exactValue
  simp only [order, valid.attachment_count, contents, and_self, ↓reduceIte] at exactValue
  simpa using exactValue

theorem initial_constructor (action : auths_codec.auths_model.CanonicalAction) (valid : Valid action) :
    auths_model.CanonicalAction.new action.profile action.media_type action.body action.permission action.requested_budget =
      ok (.Ok {action with detached_attachments := alloc.vec.Vec.new _}) := by
  rw [Constructors.canonical_action_new_exact]
  simp [valid.body_nonempty, valid.body_bound]

theorem strings_bounded (action : auths_codec.auths_model.CanonicalAction) (valid : Valid action) :
    ActionEncode.StringsBounded action := fields_earn_strings action valid.fields

theorem buffer_room (action : auths_codec.auths_model.CanonicalAction) (valid : Valid action) :
    ActionEncode.actionCost action ≤ Usize.max := by
  have envelope := ActionResources.valid_allocation_envelope action valid.fields valid.body_bound
    ⟨valid.attachment_count, valid.attachment_bytes⟩
  have portable : 16818401 ≤ Usize.max := by scalar_tac
  omega

end Auths.Codec.ActionCarrier
