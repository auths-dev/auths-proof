import Auths.Support.BorrowTransport
import Auths.Support.CurrentBorrowCarrier

/-!
Full-value adapters for the independently expanded native field shapes. An
incoming full value supplies only the selected borrow view; restoration uses
the current outgoing carrier for every unselected field. Partial sums reject
incompatible tags. No missing value, ordinary result or heap permission is
created. Native pure-type/heap/loan/source ABI adequacy remains required.
All new scripts await final elaboration.
-/
namespace Auths.Support.FullBorrowABI
open SourceClosureRegions BorrowProjection BorrowTransport
universe u

structure Channel where
  candidateShape : Shape
  selected : Plan candidateShape
  incomingShape : Shape
  outgoingShape : Shape
  incomingChange : Change candidateShape incomingShape
  outgoingChange : Change candidateShape outgoingShape

def Channel.incomingPlan (channel : Channel) : Plan channel.incomingShape :=
  mapPlan channel.incomingChange channel.selected

def Channel.outgoingPlan (channel : Channel) : Plan channel.outgoingShape :=
  mapPlan channel.outgoingChange channel.selected

def route {Atom : Expr → Type u} (channel : Channel)
    (incoming : View Atom channel.incomingPlan) : View Atom channel.outgoingPlan :=
  forwardView channel.outgoingChange channel.selected
    (backwardView channel.incomingChange channel.selected incoming)

def adapt {Atom : Expr → Type u} (channel : Channel)
    (current : Data Atom channel.outgoingShape) (incoming : Data Atom channel.incomingShape) :
    Option (Data Atom channel.outgoingShape) :=
  put channel.outgoingPlan current (route channel (get channel.incomingPlan incoming))

def wholeValue {Atom : Expr → Type u} (channel : Channel)
    (incoming : Data Atom channel.incomingShape) : Data Atom channel.outgoingShape :=
  forward channel.outgoingChange (forward (inverse channel.incomingChange) incoming)

theorem whole_ownership_needs_no_current_default {Atom : Expr → Type u} (channel : Channel)
    (whole : channel.selected = .keep) (current : Data Atom channel.outgoingShape)
    (incoming : Data Atom channel.incomingShape) :
    adapt channel current incoming = some (wholeValue channel incoming) := by
  rcases channel with ⟨shape, selected, incomingShape, outgoingShape, incomingChange, outgoingChange⟩
  dsimp only at whole
  subst selected
  rfl

/-- This witness transports the existing current value; it fills no absent
field and chooses no enum alternative. -/
def matchingIncoming {Atom : Expr → Type u} (channel : Channel)
    (current : Data Atom channel.outgoingShape) : Data Atom channel.incomingShape :=
  forward channel.incomingChange (forward (inverse channel.outgoingChange) current)

theorem matching_incoming_has_current_view {Atom : Expr → Type u} (channel : Channel)
    (current : Data Atom channel.outgoingShape) :
    route channel (get channel.incomingPlan (matchingIncoming channel current)) =
      get channel.outgoingPlan current := by
  unfold route matchingIncoming Channel.incomingPlan Channel.outgoingPlan
  rw [← extraction_commutes channel.incomingChange channel.selected]
  rw [view_forward_inverse]
  rw [extraction_commutes channel.outgoingChange channel.selected]
  rw [inverse_forward]

theorem matching_incoming_is_accepted {Atom : Expr → Type u} (channel : Channel)
    (current : Data Atom channel.outgoingShape) :
    adapt channel current (matchingIncoming channel current) = some current := by
  unfold adapt
  rw [matching_incoming_has_current_view]
  exact get_then_put _ _

theorem accepted_update_has_exact_selected_view {Atom : Expr → Type u} (channel : Channel)
    (current after : Data Atom channel.outgoingShape) (incoming : Data Atom channel.incomingShape)
    (accepted : adapt channel current incoming = some after) :
    get channel.outgoingPlan after = route channel (get channel.incomingPlan incoming) :=
  put_then_get _ _ _ _ accepted

theorem accepted_update_preserves_current_frame {Atom : Expr → Type u} (channel : Channel)
    (current after : Data Atom channel.outgoingShape) (incoming : Data Atom channel.incomingShape)
    (accepted : adapt channel current incoming = some after) :
    get (CurrentBorrowCarrier.complement channel.outgoingPlan) after =
      get (CurrentBorrowCarrier.complement channel.outgoingPlan) current :=
  CurrentBorrowCarrier.put_preserves_complement _ _ _ _ accepted

theorem unselected_incoming_data_has_no_effect {Atom : Expr → Type u} (channel : Channel)
    (current : Data Atom channel.outgoingShape) (first second : Data Atom channel.incomingShape)
    (same : get channel.incomingPlan first = get channel.incomingPlan second) :
    adapt channel current first = adapt channel current second := by
  unfold adapt
  rw [same]

theorem incoming_extraction_is_realizable {Atom : Expr → Type u} (channel : Channel)
    (incoming : Data Atom channel.incomingShape) :
    ∃ original : Data Atom channel.incomingShape,
      get channel.incomingPlan original = get channel.incomingPlan incoming := ⟨incoming, rfl⟩

end Auths.Support.FullBorrowABI
