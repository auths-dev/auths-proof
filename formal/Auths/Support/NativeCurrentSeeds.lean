import Auths.Support.NativeCaptureValue
import Auths.Support.NativeBorrowDefaults

/-!
Read current seeds from the same forward execution that produces the captured
value. Borrow keys resolve through the actual expansion instruction and its
retained exclusive-borrow shape; symbolic keys resolve by exact identity.
Returned-value paths are an independent data projection. They have no Rust
addresses or permission semantics. Source construction must connect their
indices and borrow identities to the actual typed native return. These scripts
do not prove original native environment/default/continuation or heap adequacy.
All scripts await final elaboration.
-/
namespace Auths.Support.NativeCurrentSeeds
open SourceClosureRegions BorrowProjection NativeBorrowDefaults
open NativeCaptureValue
universe u

inductive PathStep where
  | field (index : Nat)
  | mutableBorrow
  | boxed
  deriving DecidableEq, Repr

def borrowedOrigins (program : Program) (borrow : Nat) : List (Nat × Nat) :=
  program.steps.filterMap fun step => match step with
    | .mutableBorrow source actual contents => if actual = borrow then some (source, contents) else none
    | _ => none

def readSeed {Atom : Expr → Type u} (program : Program) (state : State Atom)
    (key : Key) (shape : Shape) : Option (Data Atom shape) := do
  let identity ← match key with
    | .symbolic identity => some identity
    | .borrow identity => match borrowedOrigins program identity with
      | [(source, contents)] => do
          if source ∉ state.expanded then none else do
            let borrowed ← find identity state.borrows
            match borrowed with
            | .borrow true _ body => if body = shape then some contents else none
            | _ => none
      | _ => none
  let value ← find identity state.values
  castData shape value

def readReturned {Atom : Expr → Type u} : List PathStep → Datum Atom → Option (Datum Atom)
  | [], value => some value
  | .field index :: rest, value => do
      let fields ← capturedFields value.2
      let field ← fields[index]?
      readReturned rest field
  | .mutableBorrow :: rest, ⟨.borrow true _ body, .borrow value⟩ =>
      readReturned rest ⟨body, value⟩
  | .boxed :: rest, ⟨.named .boxed body, .named value⟩ =>
      readReturned rest ⟨body, value⟩
  | _, _ => none

def readReturnedAs {Atom : Expr → Type u} (shape : Shape) (path : List PathStep)
    (value : Datum Atom) : Option (Data Atom shape) :=
  (readReturned path value).bind (castData shape)

theorem missing_symbolic_seed_is_refused {Atom : Expr → Type u} (program : Program)
    (state : State Atom) (identity : Nat) (shape : Shape)
    (missing : find identity state.values = none) :
    readSeed program state (.symbolic identity) shape = none := by
  simp [readSeed, missing]

theorem borrow_seed_needs_actual_expansion {Atom : Expr → Type u} (program : Program)
    (state : State Atom) (identity : Nat) (shape : Shape)
    (missing : borrowedOrigins program identity = []) :
    readSeed program state (.borrow identity) shape = none := by
  simp [readSeed, missing]

theorem ambiguous_borrow_seed_is_refused {Atom : Expr → Type u} (program : Program)
    (state : State Atom) (identity : Nat) (shape : Shape)
    (one two : Nat × Nat) (rest : List (Nat × Nat))
    (ambiguous : borrowedOrigins program identity = one :: two :: rest) :
    readSeed program state (.borrow identity) shape = none := by
  simp [readSeed, ambiguous]

theorem returned_field_out_of_bounds_is_refused {Atom : Expr → Type u}
    (value : Datum Atom) (fields : List (Datum Atom)) (index : Nat) (rest : List PathStep)
    (actual : capturedFields value.2 = some fields) (absent : fields[index]? = none) :
    readReturned (.field index :: rest) value = none := by
  simp [readReturned, actual, absent]

end Auths.Support.NativeCurrentSeeds
