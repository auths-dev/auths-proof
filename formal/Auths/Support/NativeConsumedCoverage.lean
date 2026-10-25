import Auths.Support.NativeProjectorKinds

/-!
Coverage of an actual incoming symbolic projection against its receiver's
owned projection. Both region scopes and both original projection types are
retained, separately from the actual fresh type. This is a conservative
structural check over complete source syntax, not a heap, pointer-identity,
current-value or whole-native-ABI theorem. All scripts await elaboration.
-/
namespace Auths.Support.NativeConsumedCoverage
open SourceClosureRegions NativeProjectorKinds

/-- Only the original free source-region identifiers belong to these scopes.
An erased or bound region is not silently assigned a free lifetime. -/
def inScope (scope : List Nat) : Region → Option Bool
  | .parameter identity => some (scope.contains identity)
  | .literalStatic => some false
  | .bound _ _ | .body _ | .erased => none

/-- Every receiver-owned region position must occur in the incoming scope at
that same structural position. All non-lifetime metadata remains exact. Fuel
exhaustion, holes, unsupported scopes or shape mismatch refuse comparison. -/
def covers : Nat → List Nat → Expr → List Nat → Expr → Option Bool
  | 0, _, _, _, _ => none
  | _, _, .natural first, _, .natural second => if first = second then some true else none
  | _, _, .bytes first, _, .bytes second => if first = second then some true else none
  | _, incoming, .region first, receiver, .region second => do
      let source ← inScope incoming first
      let target ← inScope receiver second
      pure (source || !target)
  | fuel + 1, incoming, .binder first left, receiver, .binder second right =>
      if first = second then covers fuel incoming left receiver right else none
  | fuel + 1, incoming, .node first left, receiver, .node second right => do
      if first ≠ second ∨ left.length ≠ right.length then none else
        (left.zip right).foldlM (fun covered pair => do
          let next ← covers fuel incoming pair.1 receiver pair.2
          pure (covered && next)) true
  | _, _, _, _, _ => none

structure Receipt where
  receiverSymbol : Nat
  receiverType : Expr
  receiverRegions : List Nat
  incomingSymbol : Nat
  incomingProjectionType : Expr
  incomingRegions : List Nat
  freshSymbol : Nat
  actualFreshType : Expr
  edgeType : Expr
  deriving DecidableEq, Repr

def receiptShapesAgree (fuel : Nat) (receipt : Receipt) : Bool :=
  onlyRegionsDiffer fuel receipt.receiverType receipt.edgeType &&
    onlyRegionsDiffer fuel receipt.incomingProjectionType receipt.actualFreshType &&
    onlyRegionsDiffer fuel receipt.receiverType receipt.actualFreshType

/-- Coverage is computed from the real incoming scope and receiver scope;
there is no supplied `coversAll` premise or trusted summary bit. -/
def receiptCoverage (fuel : Nat) (receipt : Receipt) : Option Bool :=
  covers fuel receipt.incomingRegions receipt.incomingProjectionType
    receipt.receiverRegions receipt.receiverType

/-- Declarative position-by-position ownership coverage. The node constructors
retain the complete ordered field spine, including empty nodes; they cannot
skip a receiver field, change a tag, or use an unrelated incoming position.
At each lifetime position, ownership by the receiver requires ownership by
the incoming scope. This relation says nothing about runtime value equality,
reference identity, availability, or the validity of an outstanding loan. -/
inductive OwnershipCoverage (incoming receiver : List Nat) : Expr → Expr → Prop where
  | natural (value : Nat) : OwnershipCoverage incoming receiver (.natural value) (.natural value)
  | bytes (value : List Nat) : OwnershipCoverage incoming receiver (.bytes value) (.bytes value)
  | region (source target : Region) (sourceOwned targetOwned : Bool)
      (sourceScope : inScope incoming source = some sourceOwned)
      (targetScope : inScope receiver target = some targetOwned)
      (includes : targetOwned = true → sourceOwned = true) :
      OwnershipCoverage incoming receiver (.region source) (.region target)
  | binder (parameters : List Nat) {source target : Expr}
      (body : OwnershipCoverage incoming receiver source target) :
      OwnershipCoverage incoming receiver (.binder parameters source) (.binder parameters target)
  | empty (tag : Tag) : OwnershipCoverage incoming receiver (.node tag []) (.node tag [])
  | field (tag : Tag) {source target : Expr} {sources targets : List Expr}
      (head : OwnershipCoverage incoming receiver source target)
      (tail : OwnershipCoverage incoming receiver (.node tag sources) (.node tag targets)) :
      OwnershipCoverage incoming receiver (.node tag (source :: sources)) (.node tag (target :: targets))

private theorem successful_conjunction_checks_every_element {α : Type}
    (compare : α → Option Bool) (values : List α) (initial : Bool)
    (accepted : values.foldlM (fun covered value => do
      let next ← compare value
      pure (covered && next)) initial = some true) :
    initial = true ∧ ∀ value ∈ values, compare value = some true := by
  induction values generalizing initial with
  | nil =>
      simp only [List.foldlM, Option.pure_def, Option.some.injEq] at accepted
      exact ⟨accepted, by simp⟩
  | cons head tail ih =>
      cases compared : compare head with
      | none => simp [List.foldlM, compared] at accepted
      | some result =>
          have rest := ih (initial && result) (by
            simpa [List.foldlM, compared] using accepted)
          have both : initial = true ∧ result = true := by simpa using rest.1
          refine ⟨both.1, ?_⟩
          intro value member
          rcases List.mem_cons.mp member with equal | member
          · subst value
            simpa [both.2] using compared
          · exact rest.2 value member

/-- A successful finite comparison earns declarative coverage of every
receiver-owned position. In particular, the Boolean result is not a supplied
coverage assumption, and no unvisited field can be covered by default.
Fuel exhaustion and unsupported lifetime syntax have no successful case. -/
theorem accepted_coverage_covers_every_receiver_owned_position
    (fuel : Nat) (incoming receiver : List Nat) (source target : Expr)
    (accepted : covers fuel incoming source receiver target = some true) :
    OwnershipCoverage incoming receiver source target := by
  induction fuel generalizing source target with
  | zero => simp [covers] at accepted
  | succ fuel ih =>
      cases source with
      | natural value =>
          cases target <;> simp [covers] at accepted
          subst_vars
          exact .natural value
      | bytes value =>
          cases target <;> simp [covers] at accepted
          subst_vars
          exact .bytes value
      | outputSlot _ => cases target <;> simp [covers] at accepted
      | region sourceRegion =>
          cases target with
          | region targetRegion =>
              cases sourceScope : inScope incoming sourceRegion with
              | none => simp [covers, sourceScope] at accepted
              | some sourceOwned =>
                  cases targetScope : inScope receiver targetRegion with
                  | none => simp [covers, sourceScope, targetScope] at accepted
                  | some targetOwned =>
                      refine .region sourceRegion targetRegion sourceOwned targetOwned sourceScope targetScope ?_
                      cases sourceOwned <;> cases targetOwned <;>
                        simp_all [covers]
          | _ => simp [covers] at accepted
      | binder parameters sourceBody =>
          cases target with
          | binder otherParameters targetBody =>
              by_cases same : parameters = otherParameters
              · subst otherParameters
                exact .binder parameters (ih sourceBody targetBody (by simpa [covers] using accepted))
              · simp [covers, same] at accepted
          | _ => simp [covers] at accepted
      | node tag sources =>
          cases target with
          | node otherTag targets =>
              by_cases same : tag = otherTag ∧ sources.length = targets.length
              · obtain ⟨rfl, sameLength⟩ := same
                have all := (successful_conjunction_checks_every_element
                  (fun pair : Expr × Expr => covers fuel incoming pair.1 receiver pair.2)
                  (sources.zip targets) true (by simpa [covers, sameLength] using accepted)).2
                induction sources generalizing targets with
                | nil =>
                    cases targets with
                    | nil => exact .empty otherTag
                    | cons _ _ => simp at sameLength
                | cons head tail listIH =>
                    cases targets with
                    | nil => simp at sameLength
                    | cons targetHead targetTail =>
                        refine .field otherTag (ih head targetHead (all (head, targetHead) (by simp))) ?_
                        apply listIH targetTail (by simpa using sameLength)
                        intro pair member
                        exact all pair (by simp [member])
              · simp [covers, not_and_or.mp same] at accepted
          | _ => simp [covers] at accepted

/-- The public receipt interface obtains coverage from its actual incoming
and receiving types/scopes. Shape agreement and runtime reconstruction remain
additional obligations; this theorem does not infer either of them. -/
theorem accepted_receipt_covers_its_actual_receiver (fuel : Nat) (receipt : Receipt)
    (accepted : receiptCoverage fuel receipt = some true) :
    OwnershipCoverage receipt.incomingRegions receipt.receiverRegions
      receipt.incomingProjectionType receipt.receiverType :=
  accepted_coverage_covers_every_receiver_owned_position fuel
    receipt.incomingRegions receipt.receiverRegions
    receipt.incomingProjectionType receipt.receiverType accepted

theorem a_missing_incoming_owned_region_is_partial
    (fuel incomingRegion receiverRegion : Nat) (incoming receiver : List Nat)
    (missing : incoming.contains incomingRegion = false)
    (owned : receiver.contains receiverRegion = true) :
    covers (fuel + 1) incoming (.region (.parameter incomingRegion))
      receiver (.region (.parameter receiverRegion)) = some false := by
  simp [covers, inScope, missing, owned]

theorem an_incoming_owned_region_covers_the_corresponding_position
    (fuel incomingRegion receiverRegion : Nat) (incoming receiver : List Nat)
    (owned : incoming.contains incomingRegion = true) :
    covers (fuel + 1) incoming (.region (.parameter incomingRegion))
      receiver (.region (.parameter receiverRegion)) = some true := by
  simp [covers, inScope, owned]

theorem a_non_lifetime_identity_change_is_not_coverage
    (fuel first second : Nat) (incoming receiver : List Nat) (different : first ≠ second) :
    covers (fuel + 1) incoming (.natural first) receiver (.natural second) = none := by
  simp [covers, different]

theorem erased_scopes_cannot_supply_coverage
    (fuel : Nat) (incoming receiver : List Nat) (region : Region) :
    covers (fuel + 1) incoming (.region .erased) receiver (.region region) = none := by
  simp [covers, inScope]

end Auths.Support.NativeConsumedCoverage
