import Auths.Codec.ActionCarrier
import Auths.Codec.PrimitiveInverse
open Aeneas Aeneas.Std Result
open auths_codec
namespace Auths.Codec.ActionWireParts
open Refinement ProtocolEncode ObjectEncode EncoderState AttachmentEncode ActionEncode

/-- Ordered semantic pieces of the independent public-action wire grammar.
Keeping prefixes explicit prevents cursor arithmetic from silently changing
which source field is consumed by a later parser. -/
def parts (action : auths_codec.auths_model.CanonicalAction) : List (List Nat) := [
  encodeHead ⟨5, 6⟩,
  encodeHead ⟨0, 0⟩,
  profileEncoding (stringBytes action.profile.id) action.profile.version.val,
  encodeHead ⟨0, 1⟩,
  payloadEncoding 3 (stringBytes action.media_type),
  encodeHead ⟨0, 2⟩,
  payloadEncoding 2 (byteList action.body.val),
  encodeHead ⟨0, 3⟩,
  permissionEncoding (stringBytes action.permission.capability) (stringBytes action.permission.resource),
  encodeHead ⟨0, 4⟩,
  optionalBudgetEncoding (action.requested_budget.map ObjectEncode.budgetView),
  encodeHead ⟨0, 5⟩,
  encodeHead ⟨4, action.detached_attachments.val.length⟩,
  attachmentsEncoding action.detached_attachments.val
]

def before (action : auths_codec.auths_model.CanonicalAction) (index : Nat) : List Nat :=
  (parts action |>.take index).flatten

def after (action : auths_codec.auths_model.CanonicalAction) (index : Nat) : List Nat :=
  (parts action |>.drop (index + 1)).flatten

theorem flatten_parts (action : auths_codec.auths_model.CanonicalAction) :
    (parts action).flatten = actionEncoding action := by
  simp only [parts, List.flatten_cons, List.flatten_nil, List.append_nil, actionEncoding]
  rfl

theorem decompose (action : auths_codec.auths_model.CanonicalAction) (index : Nat) (piece : List Nat)
    (atIndex : (parts action)[index]? = some piece) :
    actionEncoding action = before action index ++ piece ++ after action index := by
  have inside := (List.getElem?_eq_some_iff.mp atIndex).1
  have element := (List.getElem?_eq_some_iff.mp atIndex).2
  have split := List.take_append_drop index (parts action)
  rw [List.drop_eq_getElem_cons inside, element] at split
  have flattened := congrArg List.flatten split
  simpa only [List.flatten_append, List.flatten_cons, flatten_parts, before, after,
    List.append_assoc] using flattened.symm

theorem before_next (action : auths_codec.auths_model.CanonicalAction) (index : Nat) (piece : List Nat)
    (atIndex : (parts action)[index]? = some piece) :
    before action (index + 1) = before action index ++ piece := by
  have inside := (List.getElem?_eq_some_iff.mp atIndex).1
  have element := (List.getElem?_eq_some_iff.mp atIndex).2
  simp only [before, List.take_succ_eq_append_getElem inside, element,
    List.flatten_append, List.flatten_cons, List.flatten_nil, List.append_nil]

def At (input : Slice Std.U8) (action : auths_codec.auths_model.CanonicalAction)
    (self : cbor.Decoder) (index : Nat) : Prop :=
  self.input = input ∧ self.position.val = (before action index).length

theorem input_piece (input : Slice Std.U8) (action : auths_codec.auths_model.CanonicalAction)
    (self : cbor.Decoder) (index : Nat) (piece : List Nat)
    (wire : byteList input.val = actionEncoding action) (cursorAt : At input action self index)
    (atIndex : (parts action)[index]? = some piece) :
    byteList self.input.val = before action index ++ piece ++ after action index := by
  rw [cursorAt.1, wire, decompose action index piece atIndex]

theorem advance (input : Slice Std.U8) (action : auths_codec.auths_model.CanonicalAction)
    (self next : cbor.Decoder) (index : Nat) (piece : List Nat)
    (cursorAt : At input action self index) (atIndex : (parts action)[index]? = some piece)
    (position : next.position.val = (before action index).length + piece.length)
    (sameInput : next.input = self.input) : At input action next (index + 1) := by
  refine ⟨sameInput.trans cursorAt.1, ?_⟩
  rw [before_next action index piece atIndex, List.length_append]
  exact position

theorem final_position (input : Slice Std.U8) (action : auths_codec.auths_model.CanonicalAction)
    (wire : byteList input.val = actionEncoding action) :
    (before action 14).length = input.val.length := by
  have allParts : before action 14 = actionEncoding action := by
    simpa [before, parts] using flatten_parts action
  have sameLength := congrArg List.length wire
  simpa [allParts, byteList] using sameLength.symm

end Auths.Codec.ActionWireParts
