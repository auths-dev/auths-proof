import Auths.Codec.ProtocolPrimitiveInverse

open Aeneas Aeneas.Std
open AuthsProtocolCodec

namespace Auths.Codec.ProtocolPieces
open Auths.Codec.Refinement

/- Generic arithmetic for explicit independent grammar pieces. It supplies
no decoder result: each concrete source reader must earn its own step before
the cursor can be advanced to the next named schema field. -/
def before (pieces : List (List Nat)) (index : Nat) : List Nat := (pieces.take index).flatten
def after (pieces : List (List Nat)) (index : Nat) : List Nat := (pieces.drop (index + 1)).flatten

theorem decompose (pieces : List (List Nat)) (index : Nat) (piece : List Nat)
    (atIndex : pieces[index]? = some piece) :
    pieces.flatten = before pieces index ++ piece ++ after pieces index := by
  have inside := (List.getElem?_eq_some_iff.mp atIndex).1
  have element := (List.getElem?_eq_some_iff.mp atIndex).2
  have split := List.take_append_drop index pieces
  rw [List.drop_eq_getElem_cons inside, element] at split
  have flattened := congrArg List.flatten split
  simpa only [List.flatten_append, List.flatten_cons, before, after, List.append_assoc] using flattened.symm

theorem before_next (pieces : List (List Nat)) (index : Nat) (piece : List Nat)
    (atIndex : pieces[index]? = some piece) : before pieces (index + 1) = before pieces index ++ piece := by
  have inside := (List.getElem?_eq_some_iff.mp atIndex).1
  have element := (List.getElem?_eq_some_iff.mp atIndex).2
  simp only [before, List.take_succ_eq_append_getElem inside, element,
    List.flatten_append, List.flatten_cons, List.flatten_nil, List.append_nil]

def At (input : Slice Std.U8) (leading : List Nat) (pieces : List (List Nat))
    (self : cbor.Decoder) (index : Nat) : Prop :=
  self.input = input ∧ self.position.val = leading.length + (before pieces index).length

theorem input_piece (input : Slice Std.U8) (leading trailing : List Nat) (pieces : List (List Nat))
    (self : cbor.Decoder) (index : Nat) (piece : List Nat)
    (wire : byteList input.val = leading ++ pieces.flatten ++ trailing)
    (cursorAt : At input leading pieces self index) (atIndex : pieces[index]? = some piece) :
    byteList self.input.val = (leading ++ before pieces index) ++ piece ++ (after pieces index ++ trailing) := by
  rw [cursorAt.1, wire, decompose pieces index piece atIndex]
  simp only [List.append_assoc]

theorem advance (input : Slice Std.U8) (leading : List Nat) (pieces : List (List Nat))
    (self next : cbor.Decoder) (index : Nat) (piece : List Nat)
    (cursorAt : At input leading pieces self index) (atIndex : pieces[index]? = some piece)
    (position : next.position.val = (leading ++ before pieces index).length + piece.length)
    (sameInput : next.input = self.input) : At input leading pieces next (index + 1) := by
  refine ⟨sameInput.trans cursorAt.1, ?_⟩
  rw [before_next pieces index piece atIndex, List.length_append]
  simpa only [List.length_append, Nat.add_assoc] using position

theorem final_position (input : Slice Std.U8) (leading : List Nat) (pieces : List (List Nat))
    (self : cbor.Decoder) (cursorAt : At input leading pieces self pieces.length) :
    self.position.val = leading.length + pieces.flatten.length := by
  simpa only [before, List.take_length] using cursorAt.2

end Auths.Codec.ProtocolPieces
