import Auths.Support.SourceClosureRegions
import Mathlib.Data.Set.Basic

/-!
The lifetime component of a source getter input. The source signature view
must identify a mutable reference to the actual parent writer for the returned
object's region. A well-formed reference input then supplies pointee liveness
for that region, independently of which runtime writer case was selected.

`ReferenceLifetimeWF` is an explicit source-input representation premise, not
a Boolean supplied by the constructor and not complete Rust reference typing.
Actual source value/call/capture wellformedness and the native heap/loan bridge
remain required. All new scripts await final elaboration.
-/
namespace Auths.Support.WriterInputBound
open SourceClosureRegions
universe u

structure SignatureView where
  regionParameters : List Nat
  bodyRegions : Nat
  inputs : List Expr
  writerIndex : Nat
  writerType : Expr
  outputObjectRegion : Region
  deriving DecidableEq, Repr

def inSourceScope (parameters : List Nat) (bodyRegions : Nat) : Region → Bool
  | .body index => decide (index < bodyRegions)
  | region => publicRegion parameters region

def check (view : SignatureView) : Bool :=
  decide (view.regionParameters.Nodup ∧
    inSourceScope view.regionParameters view.bodyRegions view.outputObjectRegion = true ∧
    view.inputs[view.writerIndex]? =
      some (.node .mutRef [.region view.outputObjectRegion, view.writerType]))

/-- Read the actual existential self-type outlives predicate from the retained
dynamic type binder. Every constructor remains in the full source tree; this
projection supports the unquantified, single self-bound shape of the actual
source writer object. Other shapes refuse rather than guessing an annotation. -/
def dynamicObjectAnnotation : Expr → Option Region
  | .binder [] (.node .dynamicType [
      .node .genericParameters [
        .node .regionParameters [],
        .node .typeParameters [.node .typeParameter [.natural parameter, .bytes _, .natural _]],
        .node .constantParameters [], .node .traitParameters _, .node .regionPredicates _,
        .node .typePredicates [
          .binder [] (.node .predicateBinder [.node .regionParameters [],
            .node .typeOutlives [.node .typeBound [.natural 1, .natural bound], .region region]])],
        .node .associatedConstraints []],
      .node .typeBound [.natural 0, .natural body]]) =>
        if parameter = bound ∧ parameter = body then some region else none
  | _ => none

def boxedObjectAnnotation : Expr → Option Region
  | .node .boxType [.node .arguments [
      .node .regions [], .node .types [object], .node .constants [], .node .traits []]] =>
      dynamicObjectAnnotation object
  | _ => none

abbrev RegionMeaning (Point : Type u) := Region → Set Point

def TypeOutlives {Point : Type u} (regions : RegionMeaning Point)
    (typeLive : Expr → Point → Prop) (type : Expr) (region : Region) : Prop :=
  ∀ point ∈ regions region, typeLive type point

/-- Only the lifetime part of source reference wellformedness. Address validity,
exclusive permissions and source typing of other values are separate. -/
inductive ReferenceLifetimeWF {Point : Type u} (regions : RegionMeaning Point)
    (typeLive : Expr → Point → Prop) : Expr → Prop where
  | mutable (region : Region) (pointee : Expr)
      (live : TypeOutlives regions typeLive pointee region) :
      ReferenceLifetimeWF regions typeLive (.node .mutRef [.region region, pointee])
  | shared (region : Region) (pointee : Expr)
      (live : TypeOutlives regions typeLive pointee region) :
      ReferenceLifetimeWF regions typeLive (.node .sharedRef [.region region, pointee])

theorem mutable_input_pointee_outlives_borrow {Point : Type u}
    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop) (region : Region) (pointee : Expr)
    (typed : ReferenceLifetimeWF regions typeLive (.node .mutRef [.region region, pointee])) :
    TypeOutlives regions typeLive pointee region := by
  cases typed with
  | mutable _ _ live => exact live

theorem source_getter_input_supplies_object_bound {Point : Type u}
    (view : SignatureView) (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop)
    (accepted : check view = true) (input : Expr)
    (actual : view.inputs[view.writerIndex]? = some input)
    (typed : ReferenceLifetimeWF regions typeLive input) :
    TypeOutlives regions typeLive view.writerType view.outputObjectRegion := by
  have exactInput : view.inputs[view.writerIndex]? =
      some (.node .mutRef [.region view.outputObjectRegion, view.writerType]) :=
    (of_decide_eq_true accepted).2.2
  have same : input = .node .mutRef [.region view.outputObjectRegion, view.writerType] :=
    Option.some.inj (actual.symm.trans exactInput)
  subst input
  exact mutable_input_pointee_outlives_borrow _ _ _ _ typed

theorem erased_object_region_refused (view : SignatureView)
    (erased : view.outputObjectRegion = .erased) : check view = false := by
  simp [check, erased, inSourceScope, publicRegion]

theorem escaped_body_region_refused (view : SignatureView) (index : Nat)
    (body : view.outputObjectRegion = .body index) (outside : view.bodyRegions ≤ index) :
    check view = false := by
  simp [check, body, inSourceScope, Nat.not_lt.mpr outside]

theorem source_bound_can_be_narrowed {Point : Type u}
    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop) (type : Expr)
    (source target : Region) (typed : TypeOutlives regions typeLive type source)
    (within : regions target ⊆ regions source) : TypeOutlives regions typeLive type target :=
  fun point member => typed point (within member)

/-- The lifetime edge required by a borrowed Box containing a bounded object.
Reference wellformedness supplies pointee liveness over the borrow. The source
object-value interpretation must independently establish that a live pointee
keeps its object's lifetime live. Neither premise is a native hierarchy Boolean
or a supplied function result; full source heap/loan typing remains separate. -/
theorem source_reference_supplies_nested_object_edge {Point : Type u}
    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop)
    (borrow object : Region) (pointee : Expr)
    (typed : ReferenceLifetimeWF regions typeLive (.node .mutRef [.region borrow, pointee]))
    (objectLive : ∀ point, typeLive pointee point → point ∈ regions object) :
    regions borrow ⊆ regions object := by
  intro point within
  exact objectLive point (mutable_input_pointee_outlives_borrow regions typeLive borrow pointee typed point within)

/-- A source object interpretation applies to the retained exact type syntax,
not just an unrelated lifetime or a condition naming the desired edge. The
actual source heap/Box/dynamic-object typing must establish this interpretation. -/
def BoxObjectInterpretation {Point : Type u} (regions : RegionMeaning Point)
    (typeLive : Expr → Point → Prop) : Prop :=
  ∀ pointee object, boxedObjectAnnotation pointee = some object →
    ∀ point, typeLive pointee point → point ∈ regions object

theorem checked_source_object_field_supplies_nested_edge {Point : Type u}
    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop)
    (borrow object : Region) (pointee : Expr)
    (annotation : boxedObjectAnnotation pointee = some object)
    (meaning : BoxObjectInterpretation regions typeLive)
    (typed : ReferenceLifetimeWF regions typeLive (.node .mutRef [.region borrow, pointee])) :
    regions borrow ⊆ regions object :=
  source_reference_supplies_nested_object_edge regions typeLive borrow object pointee typed
    (meaning pointee object annotation)

end Auths.Support.WriterInputBound
