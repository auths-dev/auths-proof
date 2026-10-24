import Auths.Product.TemplateAstAdmission
import Auths.Product.TemplateAstTraversal

namespace Auths.Product.TemplateAst
open RequestConstruction BodyCompiler BodyCompiler.Resources

namespace Demand
def LE (first second : Demand) : Prop := first.nodes ≤ second.nodes ∧ first.pieces ≤ second.pieces ∧
  first.literals ≤ second.literals ∧ first.dynamics ≤ second.dynamics

theorem plus_assoc (first second third : Demand) : plus (plus first second) third = plus first (plus second third) := by
  cases first; cases second; cases third
  simp [plus, Nat.add_assoc]
theorem plus_comm (first second : Demand) : plus first second = plus second first := by
  cases first; cases second
  simp [plus, Nat.add_comm]
@[simp] theorem plus_zero (value : Demand) : plus value zero = value := by cases value; simp [plus, zero]
@[simp] theorem zero_plus (value : Demand) : plus zero value = value := by cases value; simp [plus, zero]
theorem le_refl (value : Demand) : LE value value := ⟨le_rfl, le_rfl, le_rfl, le_rfl⟩
theorem le_trans {first second third : Demand} (left : LE first second) (right : LE second third) : LE first third :=
  ⟨left.1.trans right.1, left.2.1.trans right.2.1, left.2.2.1.trans right.2.2.1, left.2.2.2.trans right.2.2.2⟩
theorem le_plus_left (first second : Demand) : LE first (plus first second) := by
  simp only [LE, plus]
  omega
def times (count : Nat) (value : Demand) : Demand :=
  ⟨count * value.nodes, count * value.pieces, count * value.literals, count * value.dynamics⟩
@[simp] theorem times_zero (value : Demand) : times 0 value = zero := by cases value; simp [times, zero]
@[simp] theorem times_one (value : Demand) : times 1 value = value := by cases value; simp [times]
end Demand

structure JsonSpend (before after : JsonBuild) (demand : Demand) : Prop where
  frame : JsonFrame before after
  nodes : after.nodes ≤ before.nodes + demand.nodes
  pieces : after.pieces.length ≤ before.pieces.length + demand.pieces
  literals : after.resources.literalBytes ≤ before.resources.literalBytes + demand.literals
  dynamics : after.resources.dynamicPieces ≤ before.resources.dynamicPieces + demand.dynamics

def FormRoom (before : FormBuild) (demand : Demand) : Prop :=
  FormInvariant before ∧ before.nodes + demand.nodes ≤ 64 ∧
    before.pieces.length + demand.pieces ≤ 256 ∧
    before.resources.literalBytes + demand.literals ≤ 524288 ∧
    before.resources.dynamicPieces + demand.dynamics ≤ 256

structure FormSpend (before after : FormBuild) (demand : Demand) : Prop where
  frame : FormFrame before after
  nodes : after.nodes ≤ before.nodes + demand.nodes
  pieces : after.pieces.length ≤ before.pieces.length + demand.pieces
  literals : after.resources.literalBytes ≤ before.resources.literalBytes + demand.literals
  dynamics : after.resources.dynamicPieces ≤ before.resources.dynamicPieces + demand.dynamics

theorem JsonSpend.refl (value : JsonBuild) (valid : JsonInvariant value) : JsonSpend value value Demand.zero := by
  exact ⟨JsonFrame.refl value valid, by simp [Demand.zero], by simp [Demand.zero], by simp [Demand.zero], by simp [Demand.zero]⟩
theorem FormSpend.refl (value : FormBuild) (valid : FormInvariant value) : FormSpend value value Demand.zero := by
  exact ⟨FormFrame.refl value valid, by simp [Demand.zero], by simp [Demand.zero], by simp [Demand.zero], by simp [Demand.zero]⟩

theorem JsonSpend.trans {first middle last : JsonBuild} {left right : Demand}
    (initial : JsonSpend first middle left) (remaining : JsonSpend middle last right) : JsonSpend first last (Demand.plus left right) := by
  refine ⟨initial.frame.trans remaining.frame, ?_, ?_, ?_, ?_⟩
  all_goals
    simp only [Demand.plus]
    have n₁ := initial.nodes; have n₂ := remaining.nodes
    have p₁ := initial.pieces; have p₂ := remaining.pieces
    have l₁ := initial.literals; have l₂ := remaining.literals
    have d₁ := initial.dynamics; have d₂ := remaining.dynamics
    omega

theorem FormSpend.trans {first middle last : FormBuild} {left right : Demand}
    (initial : FormSpend first middle left) (remaining : FormSpend middle last right) : FormSpend first last (Demand.plus left right) := by
  refine ⟨initial.frame.trans remaining.frame, ?_, ?_, ?_, ?_⟩
  all_goals
    simp only [Demand.plus]
    have n₁ := initial.nodes; have n₂ := remaining.nodes
    have p₁ := initial.pieces; have p₂ := remaining.pieces
    have l₁ := initial.literals; have l₂ := remaining.literals
    have d₁ := initial.dynamics; have d₂ := remaining.dynamics
    omega

theorem JsonSpend.weaken {before after : JsonBuild} {first second : Demand}
    (spent : JsonSpend before after first) (larger : Demand.LE first second) : JsonSpend before after second := by
  exact ⟨spent.frame, by have := spent.nodes; have := larger.1; omega,
    by have := spent.pieces; have := larger.2.1; omega,
    by have := spent.literals; have := larger.2.2.1; omega,
    by have := spent.dynamics; have := larger.2.2.2; omega⟩
theorem FormSpend.weaken {before after : FormBuild} {first second : Demand}
    (spent : FormSpend before after first) (larger : Demand.LE first second) : FormSpend before after second := by
  exact ⟨spent.frame, by have := spent.nodes; have := larger.1; omega,
    by have := spent.pieces; have := larger.2.1; omega,
    by have := spent.literals; have := larger.2.2.1; omega,
    by have := spent.dynamics; have := larger.2.2.2; omega⟩

theorem json_room_weaken (before : JsonBuild) (first second : Demand) (room : JsonRoom before second)
    (smaller : Demand.LE first second) : JsonRoom before first := by
  rcases room with ⟨valid, nodes, pieces, literals, dynamics⟩
  rcases smaller with ⟨n, p, l, d⟩
  exact ⟨valid, by omega, by omega, by omega, by omega⟩
theorem form_room_weaken (before : FormBuild) (first second : Demand) (room : FormRoom before second)
    (smaller : Demand.LE first second) : FormRoom before first := by
  rcases room with ⟨valid, nodes, pieces, literals, dynamics⟩
  rcases smaller with ⟨n, p, l, d⟩
  exact ⟨valid, by omega, by omega, by omega, by omega⟩

theorem json_room_after {before after : JsonBuild} {first remaining : Demand}
    (room : JsonRoom before (Demand.plus first remaining)) (spent : JsonSpend before after first) : JsonRoom after remaining := by
  rcases room with ⟨valid, nodes, pieces, literals, dynamics⟩
  simp only [Demand.plus] at nodes pieces literals dynamics
  exact ⟨spent.frame.invariant, by have := spent.nodes; omega,
    by have := spent.pieces; omega, by have := spent.literals; omega, by have := spent.dynamics; omega⟩
theorem form_room_after {before after : FormBuild} {first remaining : Demand}
    (room : FormRoom before (Demand.plus first remaining)) (spent : FormSpend before after first) : FormRoom after remaining := by
  rcases room with ⟨valid, nodes, pieces, literals, dynamics⟩
  simp only [Demand.plus] at nodes pieces literals dynamics
  exact ⟨spent.frame.invariant, by have := spent.nodes; omega,
    by have := spent.pieces; omega, by have := spent.literals; omega, by have := spent.dynamics; omega⟩

theorem json_node_admission (depth : Nat) (before : JsonBuild) (within : depth ≤ 6) (room : JsonRoom before Demand.node) :
    ∃ after, chargeNode before.nodes depth = .ok after.nodes ∧ after = { before with nodes := before.nodes + 1 } ∧ JsonSpend before after Demand.node := by
  rcases room with ⟨valid, nodes, pieces, literals, dynamics⟩
  have nextBound : before.nodes + 1 ≤ 64 := by simpa [Demand.node] using nodes
  let after : JsonBuild := { before with nodes := before.nodes + 1 }
  have nextValid : JsonInvariant after := ⟨nextBound, valid.2⟩
  refine ⟨after, by simp [chargeNode, after, within, show before.nodes < 64 by omega], rfl, ?_⟩
  exact ⟨⟨nextValid, by simp [after], by simp [after]⟩, by simp [after, Demand.node],
    by simp [after, Demand.node], by simp [after, Demand.node], by simp [after, Demand.node]⟩

theorem json_atom_admission (before : JsonBuild) (piece : NamedJson) (room : JsonRoom before (Demand.atom piece)) :
    ∃ after, pushJson before piece = .ok after ∧ JsonSpend before after (Demand.atom piece) := by
  rcases room with ⟨valid, nodes, pieces, literals, dynamics⟩
  have count : before.pieces.length < 256 := by simp only [Demand.atom] at pieces; omega
  have resources : Bounded (plus before.resources (jsonQuantity piece)) := by
    exact ⟨by simpa [plus, jsonQuantity, Demand.atom] using literals, by simpa [plus, jsonQuantity, Demand.atom] using dynamics⟩
  let after : JsonBuild := ⟨before.nodes, plus before.resources (jsonQuantity piece), before.pieces ++ [piece]⟩
  have run : pushJson before piece = .ok after := by simp [pushJson, count, add, valid.2.2.1, resources, after]
  refine ⟨after, run, json_push_frame before after piece valid run, ?_, ?_, ?_, ?_⟩ <;>
    simp [after, Demand.atom, plus, jsonQuantity]

def formAtom (piece : NamedForm) : Demand := ⟨0, 1, formLiteralSize piece, formDynamicSize piece⟩

theorem form_atom_admission (before : FormBuild) (piece : NamedForm) (nested : NestedCount piece)
    (room : FormRoom before (formAtom piece)) : ∃ after, pushForm before piece = .ok after ∧ FormSpend before after (formAtom piece) := by
  rcases room with ⟨valid, nodes, pieces, literals, dynamics⟩
  have count : before.pieces.length < 256 := by simp only [formAtom] at pieces; omega
  have resources : Bounded (plus before.resources (formQuantity piece)) := by
    exact ⟨by simpa [plus, formQuantity, formAtom] using literals, by simpa [plus, formQuantity, formAtom] using dynamics⟩
  let after : FormBuild := ⟨before.nodes, plus before.resources (formQuantity piece), before.pieces ++ [piece]⟩
  have run : pushForm before piece = .ok after := by simp [pushForm, count, formCharge, nested, add, valid.2.2.1, resources, after]
  refine ⟨after, run, form_push_frame before after piece valid run, ?_, ?_, ?_, ?_⟩ <;>
    simp [after, formAtom, plus, formQuantity]

theorem json_prefix_demand (name : Bytes) (comma : Bool) :
    Demand.LE (Demand.literal (jsonPrefix name comma)) (Demand.literal (jsonPrefix name true)) := by
  cases comma <;> simp [Demand.LE, Demand.literal, jsonPrefix]
theorem form_prefix_demand (name : Bytes) (separator : Bool) :
    Demand.LE (Demand.literal (formPrefix name separator)) (Demand.literal (formPrefix name true)) := by
  cases separator <;> simp [Demand.LE, Demand.literal, formPrefix]

end Auths.Product.TemplateAst
