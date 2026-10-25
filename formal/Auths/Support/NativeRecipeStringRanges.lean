import Auths.Support.NativeRecipeCoreFunctions

/-!
The constructor uses the checked `str::get` range interface. UTF-8 boundaries
are byte boundaries, not Unicode scalar indices. Complete original prefix and
suffix bytes are retained by the mutable dictionary methods as well. Their
write-back domain requires the same byte length and valid UTF-8, as a safe
Rust `&mut str` view does. Raw-pointer dictionary methods use the pinned Aeneas
value-carrying pointer model; this grants no aliasing/separation claim and no
Auths caller invokes them. No unchecked or mutable-source claim is introduced.
-/
open Aeneas Aeneas.Std Result

namespace AuthsNativeRecipe.NativeModel

def charBoundary (input : Str) (position : Nat) : Bool :=
  if position = 0 ∨ position = input.val.length then true
  else match input.val[position]? with
    | none => false
    | some byte => decide (byte.val < 128 ∨ 192 ≤ byte.val)

def strRange (input : Str) (range : core.ops.range.Range Std.Usize) : Option Str :=
  if valid : range.start.val ≤ range.end.val ∧ range.end.val ≤ input.val.length ∧
      charBoundary input range.start.val = true ∧ charBoundary input range.end.val = true then
    some ⟨(input.val.drop range.start.val).take (range.end.val - range.start.val), by
      have bound := input.property
      simp only [List.length_take, List.length_drop]
      omega⟩
  else none

def replaceStrRange (input : Str) (range : core.ops.range.Range Std.Usize) (replacement : Str) : Str :=
  if valid : range.start.val ≤ range.end.val ∧ range.end.val ≤ input.val.length ∧
      replacement.val.length = range.end.val - range.start.val ∧
      (_root_.String.fromUTF8? (Auths.Codec.StdModel.bytes replacement)).isSome = true then
    ⟨input.val.take range.start.val ++ replacement.val ++ input.val.drop range.end.val, by
      have bound := input.property
      simp only [List.length_append, List.length_take, List.length_drop]
      omega⟩
  else input

end AuthsNativeRecipe.NativeModel

namespace AuthsNativeRecipe.core.ops.range.RangeUsize.Insts.CoreSliceIndexSliceIndexStrStr

def get (range : core.ops.range.Range Std.Usize) (input : Str) : Result (Option Str) :=
  ok (NativeModel.strRange input range)

def index (range : core.ops.range.Range Std.Usize) (input : Str) : Result Str :=
  match NativeModel.strRange input range with
  | none => fail .panic
  | some selected => ok selected

def get_mut (range : core.ops.range.Range Std.Usize) (input : Str) : Result (Option Str × (Option Str → Str)) :=
  let selected := NativeModel.strRange input range
  ok (selected, fun replacement =>
    match selected, replacement with
    | some _, some value => NativeModel.replaceStrRange input range value
    | _, _ => input)

def index_mut (range : core.ops.range.Range Std.Usize) (input : Str) : Result (Str × (Str → Str)) :=
  match NativeModel.strRange input range with
  | none => fail .panic
  | some selected => ok (selected, NativeModel.replaceStrRange input range)

def get_unchecked (range : core.ops.range.Range Std.Usize) (input : ConstRawPtr Str) : Result (ConstRawPtr Str) :=
  match NativeModel.strRange input.v range with
  | none => fail .undef
  | some selected => ok ⟨selected⟩

def get_unchecked_mut (range : core.ops.range.Range Std.Usize) (input : MutRawPtr Str) : Result (MutRawPtr Str) :=
  match NativeModel.strRange input.v range with
  | none => fail .undef
  | some selected => ok ⟨selected⟩

end AuthsNativeRecipe.core.ops.range.RangeUsize.Insts.CoreSliceIndexSliceIndexStrStr
