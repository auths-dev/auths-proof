import Auths.Support.NativeCaptureValue

/-!
Reconstruction uses one current carrier. A focus traverses only constructors
present in every value of its indexed shape; an enum alternative is never
guessed. Updates preserve siblings from the supplied current carrier. These
are pure-data operations, not a native loan-ending or heap semantics.
All new proof scripts await final elaboration.
-/
namespace Auths.Support.CurrentBorrowCarrier
open BorrowProjection
universe u

inductive Focus : Shape → Shape → Type where
  | here {shape} : Focus shape shape
  | first {left right target} (next : Focus left target) : Focus (.product left right) target
  | second {left right target} (next : Focus right target) : Focus (.product left right) target
  | named {identity body target} (next : Focus body target) : Focus (.named identity body) target
  | borrow {mutable region body target} (next : Focus body target) : Focus (.borrow mutable region body) target

inductive Edge where
  | first | second | named | borrow
  deriving DecidableEq, Repr

inductive Origin where
  | symbolic (identity : Nat)
  | borrow (identity : Nat)
  deriving DecidableEq, Repr

def Focus.path : {root target : Shape} → Focus root target → List Edge
  | _, _, .here => []
  | _, _, .first next => .first :: next.path
  | _, _, .second next => .second :: next.path
  | _, _, .named next => .named :: next.path
  | _, _, .borrow next => .borrow :: next.path

/-- Check the focus against the retained actual native forward-value syntax.
No enum alternative, omitted field or unknown symbolic value is invented. The
full field shapes remain checked by the dependent Focus index and forward
interpretation; this independent check fixes the actual producer and position. -/
mutual
  def locates : List Edge → Origin → NativeCaptureValue.Value → Bool
    | [], .symbolic expected, .symbolic actual => expected == actual
    | [.borrow], .borrow expected, .mutableBorrow actual _ => expected == actual
    | .borrow :: rest, origin, .mutableBorrow _ contents => locates rest origin contents
    | .named :: rest, origin, .boxed contents => locates rest origin contents
    | .named :: rest, origin, .record _ fields => locatesField rest origin fields
    | _, _, _ => false
  def locatesField : List Edge → Origin → List NativeCaptureValue.Value → Bool
    | .first :: .named :: rest, origin, first :: _ => locates rest origin first
    | .second :: rest, origin, _ :: tail => locatesField rest origin tail
    | _, _, _ => false
end

def read {Atom : SourceClosureRegions.Expr → Type u} : {root target : Shape} →
    Focus root target → Data Atom root → Data Atom target
  | _, _, .here, value => value
  | _, _, .first next, .product left _ => read next left
  | _, _, .second next, .product _ right => read next right
  | _, _, .named next, .named value => read next value
  | _, _, .borrow next, .borrow value => read next value

def write {Atom : SourceClosureRegions.Expr → Type u} : {root target : Shape} →
    Focus root target → Data Atom root → Data Atom target → Data Atom root
  | _, _, .here, _, update => update
  | _, _, .first next, .product left right, update => .product (write next left update) right
  | _, _, .second next, .product left right, update => .product left (write next right update)
  | _, _, .named next, .named value, update => .named (write next value update)
  | _, _, .borrow next, .borrow value, update => .borrow (write next value update)

def liftPlan : {root target : Shape} → Focus root target → Plan target → Plan root
  | _, _, .here, plan => plan
  | _, _, .first next, plan => .product (liftPlan next plan) .skip
  | _, _, .second next, plan => .product .skip (liftPlan next plan)
  | _, _, .named next, plan => .named (liftPlan next plan)
  | _, _, .borrow next, plan => .borrow (liftPlan next plan)

def liftView {Atom : SourceClosureRegions.Expr → Type u} : {root target : Shape} →
    (focus : Focus root target) → (plan : Plan target) → View Atom plan → View Atom (liftPlan focus plan)
  | _, _, .here, _, update => update
  | _, _, .first next, plan, update => (liftView next plan update, PUnit.unit)
  | _, _, .second next, plan, update => (PUnit.unit, liftView next plan update)
  | _, _, .named next, plan, update => liftView next plan update
  | _, _, .borrow next, plan, update => liftView next plan update

def extract {Atom : SourceClosureRegions.Expr → Type u} {root target : Shape}
    (focus : Focus root target) (plan : Plan target) (current : Data Atom root) : View Atom plan :=
  get plan (read focus current)

def restore {Atom : SourceClosureRegions.Expr → Type u} {root target : Shape}
    (focus : Focus root target) (plan : Plan target) (current : Data Atom root)
    (update : View Atom plan) : Option (Data Atom root) :=
  (put plan (read focus current) update).map (write focus current)

inductive Disjoint : {root left right : Shape} → Focus root left → Focus root right → Prop where
  | firstSecond {left right a b} (first : Focus left a) (second : Focus right b) :
      Disjoint (.first first) (.second second)
  | secondFirst {left right a b} (second : Focus right a) (first : Focus left b) :
      Disjoint (.second second) (.first first)
  | first {left right a b} {one : Focus left a} {two : Focus left b}
      (next : Disjoint one two) : Disjoint (Focus.first (right := right) one) (.first two)
  | second {left right a b} {one : Focus right a} {two : Focus right b}
      (next : Disjoint one two) : Disjoint (Focus.second (left := left) one) (.second two)
  | named {identity body a b} {one : Focus body a} {two : Focus body b}
      (next : Disjoint one two) : Disjoint (Focus.named (identity := identity) one) (.named two)
  | borrow {mutable region body a b} {one : Focus body a} {two : Focus body b}
      (next : Disjoint one two) : Disjoint (Focus.borrow (mutable := mutable) (region := region) one) (.borrow two)

theorem read_write {Atom : SourceClosureRegions.Expr → Type u} {root target : Shape}
    (focus : Focus root target) (current : Data Atom root) (update : Data Atom target) :
    read focus (write focus current update) = update := by
  induction focus generalizing current with
  | here => rfl
  | first next ih => cases current with | product left right => exact ih left
  | second next ih => cases current with | product left right => exact ih right
  | named next ih => cases current with | named value => exact ih value
  | borrow next ih => cases current with | borrow value => exact ih value

theorem write_read {Atom : SourceClosureRegions.Expr → Type u} {root target : Shape}
    (focus : Focus root target) (current : Data Atom root) :
    write focus current (read focus current) = current := by
  induction focus generalizing current with
  | here => rfl
  | first next ih => cases current with | product left right => simp [read, write, ih]
  | second next ih => cases current with | product left right => simp [read, write, ih]
  | named next ih => cases current with | named value => simp [read, write, ih]
  | borrow next ih => cases current with | borrow value => simp [read, write, ih]

theorem write_preserves_disjoint_current {Atom : SourceClosureRegions.Expr → Type u}
    {root target observed : Shape} {focus : Focus root target} {observer : Focus root observed}
    (separate : Disjoint focus observer) (current : Data Atom root) (update : Data Atom target) :
    read observer (write focus current update) = read observer current := by
  induction separate generalizing current with
  | firstSecond first second => cases current with | product left right => rfl
  | secondFirst second first => cases current with | product left right => rfl
  | first next ih => cases current with | product left right => exact ih left
  | second next ih => cases current with | product left right => exact ih right
  | named next ih => cases current with | named value => exact ih value
  | borrow next ih => cases current with | borrow value => exact ih value

theorem restore_extracted_current {Atom : SourceClosureRegions.Expr → Type u} {root target : Shape}
    (focus : Focus root target) (plan : Plan target) (current : Data Atom root) :
    restore focus plan current (extract focus plan current) = some current := by
  simp [restore, extract, get_then_put, write_read]

theorem restored_view_is_update {Atom : SourceClosureRegions.Expr → Type u} {root target : Shape}
    (focus : Focus root target) (plan : Plan target) (current after : Data Atom root)
    (update : View Atom plan) (accepted : restore focus plan current update = some after) :
    extract focus plan after = update := by
  cases result : put plan (read focus current) update with
  | none => simp [restore, result] at accepted
  | some value =>
      have same : write focus current value = after := by simpa [restore, result] using accepted
      subst after
      simpa [extract, read_write] using put_then_get plan (read focus current) value update result

theorem restoration_preserves_disjoint_current {Atom : SourceClosureRegions.Expr → Type u}
    {root target observed : Shape} {focus : Focus root target} {observer : Focus root observed}
    (separate : Disjoint focus observer) (plan : Plan target) (current after : Data Atom root)
    (update : View Atom plan) (accepted : restore focus plan current update = some after) :
    read observer after = read observer current := by
  cases result : put plan (read focus current) update with
  | none => simp [restore, result] at accepted
  | some value =>
      have same : write focus current value = after := by simpa [restore, result] using accepted
      subst after
      exact write_preserves_disjoint_current separate current value

/-- Explicitly connects the local reconstruction to a plan for the entire
current carrier. Its skipped fields therefore use the current value. -/
theorem restore_is_whole_carrier_put {Atom : SourceClosureRegions.Expr → Type u}
    {root target : Shape} (focus : Focus root target) (plan : Plan target)
    (current : Data Atom root) (update : View Atom plan) :
    put (liftPlan focus plan) current (liftView focus plan update) = restore focus plan current update := by
  induction focus generalizing current with
  | here => simp [liftPlan, liftView, restore, read, write]
  | first next ih =>
      cases current with
      | product left right =>
          simp [liftPlan, liftView, put, ih, restore, read, write, Option.map_map]
  | second next ih =>
      cases current with
      | product left right =>
          simp [liftPlan, liftView, put, ih, restore, read, write, Option.map_map]
  | named next ih =>
      cases current with
      | named value => simp [liftPlan, liftView, put, ih, restore, read, write, Option.map_map]
  | borrow next ih =>
      cases current with
      | borrow value => simp [liftPlan, liftView, put, ih, restore, read, write, Option.map_map]

theorem first_focus_preserves_current_right {Atom : SourceClosureRegions.Expr → Type u}
    {left right target : Shape} (focus : Focus left target) (plan : Plan target)
    (currentLeft : Data Atom left) (currentRight : Data Atom right) (update : View Atom plan) :
    restore (.first focus) plan (.product currentLeft currentRight) update =
      (restore focus plan currentLeft update).map (fun value => Data.product value currentRight) := by
  simp [restore, read, write, Option.map_map]

theorem second_focus_preserves_current_left {Atom : SourceClosureRegions.Expr → Type u}
    {left right target : Shape} (focus : Focus right target) (plan : Plan target)
    (currentLeft : Data Atom left) (currentRight : Data Atom right) (update : View Atom plan) :
    restore (.second focus) plan (.product currentLeft currentRight) update =
      (restore focus plan currentRight update).map (Data.product currentLeft) := by
  simp [restore, read, write, Option.map_map]

/-- Each step receives the previous result. The API has no forward snapshot
argument which could silently reset siblings between updates. -/
def restoreThen {Atom : SourceClosureRegions.Expr → Type u} {root first second : Shape}
    (firstFocus : Focus root first) (firstPlan : Plan first) (firstUpdate : View Atom firstPlan)
    (secondFocus : Focus root second) (secondPlan : Plan second) (secondUpdate : View Atom secondPlan)
    (current : Data Atom root) : Option (Data Atom root) := do
  let current ← restore firstFocus firstPlan current firstUpdate
  restore secondFocus secondPlan current secondUpdate

/-- The complete observation outside an update. Partial sums retain their tag,
so a successful update cannot hide a variant switch in its frame. -/
def complement : {shape : Shape} → Plan shape → Plan shape
  | _, .keep => .skip
  | _, .skip => .keep
  | _, .empty => .empty
  | _, .product first second => .product (complement first) (complement second)
  | _, .sum first second => .sum (complement first) (complement second)
  | _, .named contents => .named (complement contents)
  | _, .borrow contents => .borrow (complement contents)

theorem put_preserves_complement {Atom : SourceClosureRegions.Expr → Type u} {shape : Shape}
    (plan : Plan shape) (current after : Data Atom shape) (update : View Atom plan)
    (accepted : put plan current update = some after) :
    get (complement plan) after = get (complement plan) current := by
  induction plan generalizing current after update with
  | keep => rfl
  | empty => cases current
  | skip =>
      have same : current = after := Option.some.inj accepted
      subst after
      rfl
  | product first second firstIH secondIH =>
      cases current with
      | product left right =>
          rcases update with ⟨updateLeft, updateRight⟩
          cases leftResult : put first left updateLeft with
          | none => simp [put, leftResult] at accepted
          | some newLeft =>
              cases rightResult : put second right updateRight with
              | none => simp [put, leftResult, rightResult] at accepted
              | some newRight =>
                  have same : Data.product newLeft newRight = after := by
                    simpa [put, leftResult, rightResult] using accepted
                  subst after
                  exact Prod.ext (firstIH left newLeft updateLeft leftResult)
                    (secondIH right newRight updateRight rightResult)
  | sum first second firstIH secondIH =>
      cases current with
      | left value =>
          cases update with
          | inl patch =>
              cases result : put first value patch with
              | none => simp [put, result] at accepted
              | some next =>
                  have same : Data.left next = after := by simpa [put, result] using accepted
                  subst after
                  exact congrArg Sum.inl (firstIH value next patch result)
          | inr patch => simp [put] at accepted
      | right value =>
          cases update with
          | inl patch => simp [put] at accepted
          | inr patch =>
              cases result : put second value patch with
              | none => simp [put, result] at accepted
              | some next =>
                  have same : Data.right next = after := by simpa [put, result] using accepted
                  subst after
                  exact congrArg Sum.inr (secondIH value next patch result)
  | named contents ih =>
      cases current with
      | named value =>
          cases result : put contents value update with
          | none => simp [put, result] at accepted
          | some next =>
              have same : Data.named next = after := by simpa [put, result] using accepted
              subst after
              exact ih value next update result
  | borrow contents ih =>
      cases current with
      | borrow value =>
          cases result : put contents value update with
          | none => simp [put, result] at accepted
          | some next =>
              have same : Data.borrow next = after := by simpa [put, result] using accepted
              subst after
              exact ih value next update result

theorem restoration_preserves_whole_frame {Atom : SourceClosureRegions.Expr → Type u}
    {root target : Shape} (focus : Focus root target) (plan : Plan target)
    (current after : Data Atom root) (update : View Atom plan)
    (accepted : restore focus plan current update = some after) :
    get (complement (liftPlan focus plan)) after = get (complement (liftPlan focus plan)) current :=
  put_preserves_complement (liftPlan focus plan) current after (liftView focus plan update)
    ((restore_is_whole_carrier_put focus plan current update).trans accepted)

end Auths.Support.CurrentBorrowCarrier
