import Auths.Support.NativeValuePacking
import Auths.Support.BorrowViewCompatibility
import Auths.Support.NativeBindingWiring

/-!
Independent value-reference flow for actual generated native bindings. An
assignment follows an explicit earlier let expression, never a missing symbol's
default metadata. Sources describe values only; they merge no symbolic identity,
borrow view, region or authority. Output descriptors check existing references
without pretending an uncomputed helper result is an initial value. Complete
program evaluation and Rust loan/permission adequacy remain separate.
All scripts await final elaboration.
-/
namespace Auths.Support.NativeInputCompatibility
open NativeDefaultBindings NativePurePayload NativePureExpressions

inductive Kind where
  | root | incoming
  deriving DecidableEq, Repr

structure Source where
  kind : Kind
  index : Nat
  type : Ty
  deriving DecidableEq, Repr

structure Cell where
  variable : Variable
  source : Source
  deriving DecidableEq, Repr

abbrev Environment := Table Cell

structure Alias where
  target : Variable
  source : Variable
  deriving DecidableEq, Repr

structure Read where
  variable : Variable
  source : Source
  deriving DecidableEq, Repr

inductive Operation where
  | alias (binding : Alias)
  | output (current incoming : Read)
  deriving DecidableEq, Repr

def read (environment : Environment) (variable : Variable) : Option Source := do
  let cell ← lookup variable.identity environment
  if cell.variable = variable ∧ cell.source.type = variable.type then some cell.source else none

def validRead (environment : Environment) (reference : Read) : Bool :=
  decide (read environment reference.variable = some reference.source)

def step (environment : Environment) : Operation → Option Environment
  | .alias binding => do
      if (lookup binding.target.identity environment).isSome then none else do
        let source ← read environment binding.source
        if source.type ≠ binding.target.type then none else
          pure (put binding.target.identity ⟨binding.target, source⟩ environment)
  | .output current incoming =>
      if validRead environment current && validRead environment incoming then some environment else none

def scan : Environment → List Operation → Option (List Environment)
  | _, [] => some []
  | environment, first :: rest => do
      let next ← step environment first
      let following ← scan next rest
      pure (next :: following)

universe u

theorem compatible_helper_has_success {typing : AtomTyping} {Atom : Ty → Type u} {layout type}
    (builtins : Builtins) (fuel : Nat) (witness : NativeValuePacking.Root layout type)
    (channel : FullBorrowABI.Channel) (incoming : Codec typing channel.incomingShape layout)
    (outgoing : Codec typing channel.outgoingShape layout) (current input : Value Atom layout)
    (valid : BorrowViewCompatibility.Native.Compatible channel incoming outgoing current input)
    (enough : NativeValuePacking.rootFuel witness ≤ fuel) :
    expected builtins fuel type (adaptNative channel incoming outgoing current input) =
      some (NativeValuePacking.success builtins witness
        (BorrowViewCompatibility.Native.restore channel incoming outgoing current input valid)) := by
  rw [BorrowViewCompatibility.Native.adapt_is_total_on_compatible channel incoming outgoing current input valid]
  exact NativeValuePacking.expected_some_is_success builtins fuel witness _ enough

theorem whole_input_is_compatible {typing : AtomTyping} {Atom : Ty → Type u} {inputLayout outputLayout}
    (channel : FullBorrowABI.Channel) (whole : channel.selected = .keep)
    (incoming : Codec typing channel.incomingShape inputLayout)
    (outgoing : Codec typing channel.outgoingShape outputLayout)
    (current : Value Atom outputLayout) (input : Value Atom inputLayout) :
    BorrowViewCompatibility.Native.Compatible channel incoming outgoing current input := by
  unfold BorrowViewCompatibility.Native.Compatible BorrowViewCompatibility.Channel.Compatible
  rcases channel with ⟨shape, selected, incomingShape, outgoingShape, incomingChange, outgoingChange⟩
  dsimp only at whole
  subst selected
  trivial

end Auths.Support.NativeInputCompatibility
