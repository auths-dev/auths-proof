import Auths.Support.NativeRootPayload
import Auths.Support.NativeBorrowDefaults
import Auths.Support.CurrentBorrowCarrier
import Auths.Support.NativeBorrowWiring

/-!
Conditional installation of a given-back view from a proposed native argument.
A source storage coordinate does not identify a current symbolic version.
Every installation therefore requires a separate correspondence proof for its
exact given-back channel. Sharing an argument or a focus discharges no such
proof. The source ending semantics must supply the post-ending environment;
this module neither constructs that environment nor proves native/source
adequacy. Scripts await final elaboration.
-/
namespace Auths.Support.NativeRootBindings
open SourceClosureRegions BorrowProjection CurrentBorrowCarrier NativeRootPayload
universe u

/-- Keep the immediate producer and ending occurrence, even when two channels
have the same static source-root coordinates. -/
structure Channel where
  target : Nat
  immediate : NativeBorrowDefaults.Key
  group : Nat
  event : Nat
  level : Nat
  position : Nat
  deriving DecidableEq, Repr

/-- Full original symbolic types distinguish instantiations and current
versions. No native payload value or earlier default is substituted. -/
structure SourceSymbol where
  identity : Nat
  type : Expr
  deriving DecidableEq, Repr

inductive SourceProjector where
  | empty (annotation : Expr)
  | loan (annotation : Expr) (ended : Bool) (original : SourceSymbol)
      (consumed borrows : List (SourceSymbol × SourceProjector))
  | borrow (annotation : Expr) (original : SourceSymbol)
      (givenBack : Option SourceSymbol) (loans : List (SourceSymbol × SourceProjector))
  deriving DecidableEq, Repr

structure ProjectorPort where
  symbol : SourceSymbol
  givenBack : Bool
  level : Nat
  path : List NativeBorrowWiring.Edge
  deriving DecidableEq, Repr

/-- Independently select the metadata channels at an actual ending level.
Every reprojection subtree remains present even when its header is not selected.
This finite syntax check does not evaluate an ending or prove a value relation. -/
def selectSourcePorts : Nat → Nat → Nat → List NativeBorrowWiring.Edge →
    SourceProjector → Option (List ProjectorPort)
  | 0, _, _, _, _ => none
  | fuel + 1, selected, current, path, tree => do
      let one (path : List NativeBorrowWiring.Edge) (given : Bool) (symbol : SourceSymbol) :=
        if selected = current then [⟨symbol, given, current, path⟩] else []
      let edges (tag : Nat → NativeBorrowWiring.Edge) (pairs : List (SourceSymbol × SourceProjector)) :=
        pairs.zipIdx.foldlM (fun result (pair, index) => do
          let child ← selectSourcePorts fuel selected (current + 1) (path ++ [tag index]) pair.2
          pure (result ++ child)) []
      match tree with
      | .empty _ => pure []
      | .loan _ ended original consumed borrows =>
          if !ended && decide (selected = current) then none else do
            let consumedChildren ← edges NativeBorrowWiring.Edge.consumed consumed
            let borrowChildren ← edges NativeBorrowWiring.Edge.borrowReprojection borrows
            let header := if !ended then [] else if consumed.isEmpty then one path false original
              else consumed.zipIdx.flatMap fun (pair, index) => one (path ++ [.consumed index]) false pair.1
            pure (header ++ consumedChildren ++ borrowChildren)
      | .borrow _ _ givenBack loans =>
          if givenBack.isNone && decide (selected = current) then none else do
            let children ← edges NativeBorrowWiring.Edge.loanReprojection loans
            pure ((givenBack.toList.flatMap (one path true)) ++ children)

structure NestedReturn where
  event : Nat
  priorEvent : Nat
  abstraction : Nat
  priorAbstraction : Nat
  given : ProjectorPort
  consumed : ProjectorPort
  priorConsumed : ProjectorPort
  deriving DecidableEq, Repr

private def projectorPrefix : List NativeBorrowWiring.Edge → List NativeBorrowWiring.Edge → Bool
  | [], _ => true
  | one :: rest, two :: next => one == two && projectorPrefix rest next
  | _, _ => false

/-- The nested loan return was consumed earlier by this same abstraction,
at a strictly higher level, before the outer given-back header is bound.
This records a continuation dependency, not an equality of payload values. -/
def validNestedReturn (receipt : NestedReturn) : Bool :=
  decide (receipt.priorEvent < receipt.event) &&
    receipt.abstraction == receipt.priorAbstraction &&
    receipt.given.givenBack && !receipt.consumed.givenBack &&
    decide (receipt.given.level < receipt.consumed.level) &&
    projectorPrefix receipt.given.path receipt.consumed.path &&
    receipt.consumed == receipt.priorConsumed

/-- Only a split into distinct product fields establishes disjointness.
Prefixes, shared paths and unknown differences retain a correspondence
obligation. Borrow/nominal edges never establish value equality. -/
def disjointPaths : List Edge → List Edge → Bool
  | .first :: _, .second :: _ | .second :: _, .first :: _ => true
  | one :: rest, two :: next => if one == two then disjointPaths rest next else false
  | _, _ => false

theorem a_shared_path_discharges_no_correspondence (path : List Edge) :
    disjointPaths path path = false := by
  induction path with
  | nil => rfl
  | cons edge rest ih => cases edge <;> simp [disjointPaths, ih]

/-- Path disjointness proves only separation within the indexed logical
carrier. It establishes no Rust heap alias/permission fact. -/
theorem disjoint_paths_separate_carrier_fields {root left right : Shape}
    (one : Focus root left) (two : Focus root right)
    (checked : disjointPaths one.path two.path = true) : Disjoint one two := by
  induction one generalizing right with
  | here => cases two <;> simp [Focus.path, disjointPaths] at checked
  | first next ih =>
      cases two with
      | here => simp [Focus.path, disjointPaths] at checked
      | first other =>
          exact .first (ih other (by simpa [Focus.path, disjointPaths] using checked))
      | second other => exact .firstSecond next other
  | second next ih =>
      cases two with
      | here => simp [Focus.path, disjointPaths] at checked
      | first other => exact .secondFirst next other
      | second other =>
          exact .second (ih other (by simpa [Focus.path, disjointPaths] using checked))
  | named next ih =>
      cases two with
      | here => simp [Focus.path, disjointPaths] at checked
      | named other =>
          exact .named (ih other (by simpa [Focus.path, disjointPaths] using checked))
  | borrow next ih =>
      cases two with
      | here => simp [Focus.path, disjointPaths] at checked
      | borrow other =>
          exact .borrow (ih other (by simpa [Focus.path, disjointPaths] using checked))

structure ArgumentSlot where
  group : Nat
  level : Nat
  position : Nat
  deriving DecidableEq, Repr

structure Request where
  channel : Channel
  slot : ArgumentSlot
  path : List Edge
  deriving DecidableEq, Repr

/-- Detect proposed sharing; a false result is not an adequacy proof either.
Every request still needs its own `Represents` proof. -/
def requiresJointCorrespondence (one two : Request) : Bool :=
  one.slot == two.slot && one.channel.target != two.channel.target &&
    !disjointPaths one.path two.path

theorem same_slot_overlapping_versions_require_joint_correspondence
    (one two : Request) (slot : one.slot = two.slot)
    (versions : one.channel.target ≠ two.channel.target)
    (overlap : disjointPaths one.path two.path = false) :
    requiresJointCorrespondence one two = true := by
  simp [requiresJointCorrespondence, slot, versions, overlap]

/-- This is an outstanding refinement obligation, not a condition inferred
from a source origin. `sourceAfter` must be related to the actual source ending
by the enclosing refinement theorem. Its values are never an execution oracle. -/
def Represents {typing : AtomTyping} {Atom : NativeType → Type u}
    {root target : Shape} {layout : Layout} (codec : Codec typing root layout)
    (focus : Focus root target) (selected : Plan target) (channel : Channel)
    (sourceAfter : NativeBorrowDefaults.Current (SourceAtom typing Atom))
    (argument : Value Atom layout) : Prop :=
  NativeBorrowDefaults.readCurrent sourceAfter (.symbolic channel.target) target selected =
    some (get selected (read focus (decode codec argument)))

def install {typing : AtomTyping} {Atom : NativeType → Type u}
    {root target : Shape} {layout : Layout} (codec : Codec typing root layout)
    (focus : Focus root target) (selected : Plan target) (channel : Channel)
    (current sourceAfter : NativeBorrowDefaults.Current (SourceAtom typing Atom))
    (argument : Value Atom layout) (_agrees : Represents codec focus selected channel sourceAfter argument) :
    NativeBorrowDefaults.Current (SourceAtom typing Atom) :=
  let value := get selected (read focus (decode codec argument))
  fun key => if key = .symbolic channel.target then some ⟨target, selected, value⟩ else current key

theorem installed_view_is_exact_argument_projection {typing : AtomTyping} {Atom : NativeType → Type u}
    {root target : Shape} {layout : Layout} (codec : Codec typing root layout)
    (focus : Focus root target) (selected : Plan target) (channel : Channel)
    (current sourceAfter : NativeBorrowDefaults.Current (SourceAtom typing Atom)) (argument : Value Atom layout)
    (agrees : Represents codec focus selected channel sourceAfter argument) :
    NativeBorrowDefaults.readCurrent (install codec focus selected channel current sourceAfter argument agrees)
      (.symbolic channel.target) target selected = some (get selected (read focus (decode codec argument))) := by
  simp [install, NativeBorrowDefaults.readCurrent, NativeBorrowDefaults.castEntry]

theorem installation_refines_exact_source_version {typing : AtomTyping} {Atom : NativeType → Type u}
    {root target : Shape} {layout : Layout} (codec : Codec typing root layout)
    (focus : Focus root target) (selected : Plan target) (channel : Channel)
    (current sourceAfter : NativeBorrowDefaults.Current (SourceAtom typing Atom)) (argument : Value Atom layout)
    (agrees : Represents codec focus selected channel sourceAfter argument) :
    NativeBorrowDefaults.readCurrent (install codec focus selected channel current sourceAfter argument agrees)
      (.symbolic channel.target) target selected =
      NativeBorrowDefaults.readCurrent sourceAfter (.symbolic channel.target) target selected := by
  rw [installed_view_is_exact_argument_projection]
  exact agrees.symm

theorem other_current_versions_are_preserved {typing : AtomTyping} {Atom : NativeType → Type u}
    {root target : Shape} {layout : Layout} (codec : Codec typing root layout)
    (focus : Focus root target) (selected : Plan target) (channel : Channel)
    (current sourceAfter : NativeBorrowDefaults.Current (SourceAtom typing Atom)) (argument : Value Atom layout)
    (agrees : Represents codec focus selected channel sourceAfter argument)
    (key : NativeBorrowDefaults.Key) (different : key ≠ .symbolic channel.target) :
    install codec focus selected channel current sourceAfter argument agrees key = current key := by
  simp [install, different]

theorem other_source_version_reads_are_preserved {typing : AtomTyping} {Atom : NativeType → Type u}
    {root target observed : Shape} {layout : Layout} (codec : Codec typing root layout)
    (focus : Focus root target) (selected : Plan target) (channel : Channel)
    (current sourceAfter : NativeBorrowDefaults.Current (SourceAtom typing Atom)) (argument : Value Atom layout)
    (agrees : Represents codec focus selected channel sourceAfter argument)
    (identity : Nat) (plan : Plan observed) (different : identity ≠ channel.target) :
    NativeBorrowDefaults.readCurrent (install codec focus selected channel current sourceAfter argument agrees)
      (.symbolic identity) observed plan = NativeBorrowDefaults.readCurrent current (.symbolic identity) observed plan := by
  simp [NativeBorrowDefaults.readCurrent, install, different]

/-- A sibling installation cannot change a given-back channel's source
correspondence. Both witnesses refer to the actual source post-ending state,
independently of the order in which the distinct native keys are installed. -/
theorem installations_commute_for_distinct_versions {typing : AtomTyping} {Atom : NativeType → Type u}
    {oneRoot oneTarget twoRoot twoTarget : Shape} {oneLayout twoLayout : Layout}
    (oneCodec : Codec typing oneRoot oneLayout) (twoCodec : Codec typing twoRoot twoLayout)
    (oneFocus : Focus oneRoot oneTarget) (twoFocus : Focus twoRoot twoTarget)
    (onePlan : Plan oneTarget) (twoPlan : Plan twoTarget) (one two : Channel)
    (current sourceAfter : NativeBorrowDefaults.Current (SourceAtom typing Atom))
    (oneArgument : Value Atom oneLayout) (twoArgument : Value Atom twoLayout)
    (oneAgrees : Represents oneCodec oneFocus onePlan one sourceAfter oneArgument)
    (twoAgrees : Represents twoCodec twoFocus twoPlan two sourceAfter twoArgument)
    (distinct : one.target ≠ two.target) :
    install twoCodec twoFocus twoPlan two
      (install oneCodec oneFocus onePlan one current sourceAfter oneArgument oneAgrees)
      sourceAfter twoArgument twoAgrees =
    install oneCodec oneFocus onePlan one
      (install twoCodec twoFocus twoPlan two current sourceAfter twoArgument twoAgrees)
      sourceAfter oneArgument oneAgrees := by
  funext key
  by_cases first : key = .symbolic one.target
  · subst key
    simp [install, distinct]
  · by_cases second : key = .symbolic two.target
    · subst key
      simp [install, Ne.symm distinct]
    · simp [install, first, second]

/-- A shared argument at the same focus imposes a real relation on the source
versions. Origin/type equality cannot supply this premise. -/
theorem same_projection_requires_equal_source_views {typing : AtomTyping} {Atom : NativeType → Type u}
    {root target : Shape} {layout : Layout} (codec : Codec typing root layout)
    (focus : Focus root target) (selected : Plan target) (first second : Channel)
    (sourceAfter : NativeBorrowDefaults.Current (SourceAtom typing Atom)) (argument : Value Atom layout)
    (one : Represents codec focus selected first sourceAfter argument)
    (two : Represents codec focus selected second sourceAfter argument) :
    NativeBorrowDefaults.readCurrent sourceAfter (.symbolic first.target) target selected =
      NativeBorrowDefaults.readCurrent sourceAfter (.symbolic second.target) target selected :=
  one.trans two.symm

theorem unequal_source_views_cannot_share_projection {typing : AtomTyping} {Atom : NativeType → Type u}
    {root target : Shape} {layout : Layout} (codec : Codec typing root layout)
    (focus : Focus root target) (selected : Plan target) (first second : Channel)
    (sourceAfter : NativeBorrowDefaults.Current (SourceAtom typing Atom))
    (different : NativeBorrowDefaults.readCurrent sourceAfter (.symbolic first.target) target selected ≠
      NativeBorrowDefaults.readCurrent sourceAfter (.symbolic second.target) target selected) :
    ¬ ∃ argument : Value Atom layout,
      Represents codec focus selected first sourceAfter argument ∧
      Represents codec focus selected second sourceAfter argument := by
  rintro ⟨argument, one, two⟩
  exact different (same_projection_requires_equal_source_views codec focus selected first second sourceAfter argument one two)

end Auths.Support.NativeRootBindings
