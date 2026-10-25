import Auths.Support.BorrowProjection
import Auths.Support.FullBorrowABI
import Auths.Support.NativePayloadCodec

/-!
Complete field payloads for the supported closed native Pure.ty fragment.
Native nominal/variant/field identities survive; source borrow and Box wrappers
are transparent here. These are logical native field values, not Rust pointers
or a proof of the pinned translator's complete expression lowering. The source
constructor must independently derive the native schemas and every codec.
All scripts await the final elaboration and axiom audit.
-/
namespace Auths.Support.NativePurePayload
open SourceClosureRegions BorrowProjection
universe u

inductive Ty where
  | nominal (identity : Nat) (arguments : List Ty)
  | tuple (arguments : List Ty)
  | literal (kind : Nat)
  | never
  | arrow (input output : Ty)
  | result (output : Ty)
  | error
  deriving DecidableEq, Repr

/-- The field-value stage specializes the shared codec to its native type
fragment. Whole-signature carriers use the same codec with full type syntax. -/
abbrev Label := NativePayloadCodec.Label Ty
abbrev Layout := NativePayloadCodec.Layout Ty
abbrev Value := @NativePayloadCodec.Value Ty
abbrev AtomTyping := NativePayloadCodec.AtomTyping Ty
abbrev SourceAtom := @NativePayloadCodec.SourceAtom Ty
abbrev atomForward := @NativePayloadCodec.atomForward Ty
abbrev atomBackward := @NativePayloadCodec.atomBackward Ty
abbrev Codec := @NativePayloadCodec.Codec Ty
abbrev encode := @NativePayloadCodec.encode Ty
abbrev decode := @NativePayloadCodec.decode Ty
export NativePayloadCodec (decode_encode encode_decode missing_atom_has_no_value)

/-- Complete native field values enter the selected-view adapter only through
the independently constructed incoming/outgoing codecs. -/
def adaptNative {typing : AtomTyping} {Atom : Ty → Type u} {inputLayout outputLayout}
    (channel : FullBorrowABI.Channel)
    (incoming : Codec typing channel.incomingShape inputLayout)
    (outgoing : Codec typing channel.outgoingShape outputLayout)
    (current : Value Atom outputLayout) (input : Value Atom inputLayout) :
    Option (Value Atom outputLayout) :=
  (FullBorrowABI.adapt channel (decode outgoing current) (decode incoming input)).map (encode outgoing)

def matchingNativeInput {typing : AtomTyping} {Atom : Ty → Type u} {inputLayout outputLayout}
    (channel : FullBorrowABI.Channel)
    (incoming : Codec typing channel.incomingShape inputLayout)
    (outgoing : Codec typing channel.outgoingShape outputLayout)
    (current : Value Atom outputLayout) : Value Atom inputLayout :=
  encode incoming (FullBorrowABI.matchingIncoming channel (decode outgoing current))

theorem matching_native_input_is_accepted {typing : AtomTyping} {Atom : Ty → Type u}
    {inputLayout outputLayout} (channel : FullBorrowABI.Channel)
    (incoming : Codec typing channel.incomingShape inputLayout)
    (outgoing : Codec typing channel.outgoingShape outputLayout)
    (current : Value Atom outputLayout) :
    adaptNative channel incoming outgoing current (matchingNativeInput channel incoming outgoing current) =
      some current := by
  simp only [adaptNative, matchingNativeInput, decode_encode,
    FullBorrowABI.matching_incoming_is_accepted, Option.map_some, encode_decode]

theorem accepted_native_decodes_to_adapter {typing : AtomTyping} {Atom : Ty → Type u}
    {inputLayout outputLayout} (channel : FullBorrowABI.Channel)
    (incoming : Codec typing channel.incomingShape inputLayout)
    (outgoing : Codec typing channel.outgoingShape outputLayout)
    (current after : Value Atom outputLayout) (input : Value Atom inputLayout)
    (accepted : adaptNative channel incoming outgoing current input = some after) :
    FullBorrowABI.adapt channel (decode outgoing current) (decode incoming input) =
      some (decode outgoing after) := by
  cases result : FullBorrowABI.adapt channel (decode outgoing current) (decode incoming input) with
  | none => simp [adaptNative, result] at accepted
  | some value =>
      have same : encode outgoing value = after := Option.some.inj (by simpa [adaptNative, result] using accepted)
      simpa only [result, ← same, decode_encode] using result

theorem accepted_native_preserves_current_frame {typing : AtomTyping} {Atom : Ty → Type u}
    {inputLayout outputLayout} (channel : FullBorrowABI.Channel)
    (incoming : Codec typing channel.incomingShape inputLayout)
    (outgoing : Codec typing channel.outgoingShape outputLayout)
    (current after : Value Atom outputLayout) (input : Value Atom inputLayout)
    (accepted : adaptNative channel incoming outgoing current input = some after) :
    get (CurrentBorrowCarrier.complement channel.outgoingPlan) (decode outgoing after) =
      get (CurrentBorrowCarrier.complement channel.outgoingPlan) (decode outgoing current) :=
  FullBorrowABI.accepted_update_preserves_current_frame channel _ _ _
    (accepted_native_decodes_to_adapter channel incoming outgoing current after input accepted)

theorem unselected_native_input_has_no_effect {typing : AtomTyping} {Atom : Ty → Type u}
    {inputLayout outputLayout} (channel : FullBorrowABI.Channel)
    (incoming : Codec typing channel.incomingShape inputLayout)
    (outgoing : Codec typing channel.outgoingShape outputLayout)
    (current : Value Atom outputLayout) (first second : Value Atom inputLayout)
    (same : get channel.incomingPlan (decode incoming first) = get channel.incomingPlan (decode incoming second)) :
    adaptNative channel incoming outgoing current first = adaptNative channel incoming outgoing current second := by
  unfold adaptNative
  rw [FullBorrowABI.unselected_incoming_data_has_no_effect channel _ _ _ same]

end Auths.Support.NativePurePayload
