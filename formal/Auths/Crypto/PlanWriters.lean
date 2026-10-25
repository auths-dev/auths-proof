import Auths.Crypto.PlanWire
import Auths.Crypto.SigningObjectWriters
import Auths.Verifier.StatusLeaves

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.PlanWriters
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Crypto.SigningObjectWriters

/- Source representation is projected into a separate tree grammar. The
projection invokes no encoder/decoder/hash and preserves each child in order.
The actual source recursion and indexed collection loop are proved together;
no assumed Auths callback or successful recursive call occurs in the root
statement. Native space is an explicit input envelope. -/
mutual
  def viewPlan (plan : auths_model.AuthorizationPlan) : PlanWire.Plan :=
    match plan with | .mk node => viewNode node
  termination_by sizeOf plan

  def viewNode (node : auths_model.AuthorizationPlanNode) : PlanWire.Plan :=
    match node with
    | .Proof reference => .proof (byteList reference.val)
    | .AllOf members => .allOf (viewMembers members)
    | .AnyOf members => .anyOf (viewMembers members)
    | .KOfN required members => .kOfN required.val (viewMembers members)
  termination_by sizeOf node

  def viewMembers (members : alloc.vec.Vec auths_model.AuthorizationPlan) : List PlanWire.Plan :=
    match members with | .mk _ elements _ => viewElements elements
  termination_by sizeOf members

  def viewElements {n : Nat} (elements : alloc.vec.SizedList auths_model.AuthorizationPlan n) :
      List PlanWire.Plan :=
    match elements with
    | .nil => []
    | .cons head tail => viewPlan head :: viewElements tail
  termination_by sizeOf elements
end

def cost (plan : auths_model.AuthorizationPlan) : Nat := PlanWire.cost (viewPlan plan)

theorem elements_count {n : Nat} (elements : alloc.vec.SizedList auths_model.AuthorizationPlan n) :
    (viewElements elements).length = n := by
  induction elements with
  | nil => rfl
  | cons head tail ih => simpa only [viewElements, List.length_cons] using congrArg Nat.succ ih

theorem members_count (members : alloc.vec.Vec auths_model.AuthorizationPlan) :
    (viewMembers members).length = members.val.length := by
  cases members with
  | mk n elements bounded =>
    simp only [viewMembers, elements_count, auths_composition.alloc.vec.Vec.val,
      auths_composition.alloc.vec.SizedList.length]

def NodeCorrect (plan : auths_model.AuthorizationPlan) : Prop :=
  ∀ (self : cbor.Encoder), self.output.val.length + cost plan ≤ Usize.max →
    encode.encode_authorization_plan_to self plan ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ PlanWire.encode (viewPlan plan) ⦄

def ElementsCorrect {n : Nat} (elements : alloc.vec.SizedList auths_model.AuthorizationPlan n) : Prop :=
  ∀ (members : Slice auths_model.AuthorizationPlan) (position : Std.Usize) (self : cbor.Encoder),
    members.val.drop position.val = elements.toList →
    self.output.val.length + PlanWire.childrenCost (viewElements elements) ≤ Usize.max →
    encode.encode_plan_members_loop self members position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++
        (PlanWire.encodeChildren (viewElements elements)).flatten ⦄

theorem nil_correct : ElementsCorrect
    (auths_composition.alloc.vec.SizedList.nil : alloc.vec.SizedList auths_model.AuthorizationPlan 0) := by
  intro members position self remaining space
  have finished : ¬ position < members.len := by
    have length := congrArg List.length remaining
    simp only [auths_composition.alloc.vec.SizedList.toList, List.length_drop, List.length_nil] at length
    simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
    omega
  rw [encode.encode_plan_members_loop.eq_def]
  simp [finished, viewElements, PlanWire.encodeChildren, spec_ok]

theorem cons_correct {n : Nat} (head : auths_model.AuthorizationPlan)
    (tail : alloc.vec.SizedList auths_model.AuthorizationPlan n)
    (headCorrect : NodeCorrect head) (tailCorrect : ElementsCorrect tail) :
    ElementsCorrect (.cons head tail) := by
  intro members position self remaining space
  simp only [auths_composition.alloc.vec.SizedList.toList] at remaining
  obtain ⟨guard, atHead⟩ := Auths.StatusSelection.indexed_head members position head tail.toList remaining
  obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
    Auths.StatusSelection.indexed_next members position head tail.toList remaining
  have headSpace : self.output.val.length + cost head ≤ Usize.max := by
    simp only [viewElements, PlanWire.childrenCost, cost] at *
    omega
  rw [encode.encode_plan_members_loop.eq_def]
  simp only [guard, ↓reduceIte, core.option.Option.is_none, atHead, bind_tc_ok]
  step with headCorrect self headSpace as ⟨verdict, after, success, written⟩
  simp only [success, bind_tc_ok, increment]
  have actualLength := output_length written
  have headBound := PlanWire.encode_length (viewPlan head)
  have tailSpace : after.output.val.length + PlanWire.childrenCost (viewElements tail) ≤ Usize.max := by
    simp only [viewElements, PlanWire.childrenCost, cost] at space
    omega
  apply spec_mono (tailCorrect members next after nextRemaining tailSpace)
  rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
  refine ⟨noFailure, ?_⟩
  rw [encoded, written]
  simp [viewElements, PlanWire.encodeChildren, List.append_assoc]

@[step] theorem members_exact (self : cbor.Encoder) (members : alloc.vec.Vec auths_model.AuthorizationPlan)
    (correct : ElementsCorrect members.elements)
    (space : self.output.val.length + 9 + PlanWire.childrenCost (viewMembers members) ≤ Usize.max) :
    encode.encode_plan_members self (alloc.vec.Vec.deref members) ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (PlanWire.encodeChildren (viewMembers members)) ⦄ := by
  unfold encode.encode_plan_members
  step with ProtocolWriter.array_exact self (Slice.len (alloc.vec.Vec.deref members)) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := encodeHead_length_le_nine ⟨4, members.val.length⟩
  have loopSpace : afterHeader.output.val.length + PlanWire.childrenCost (viewMembers members) ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  have sameView : viewMembers members = viewElements members.elements := by cases members; rfl
  rw [sameView] at loopSpace
  step with correct (alloc.vec.Vec.deref members) 0#usize afterHeader
    (by simp [alloc.vec.deref_exact, auths_composition.alloc.vec.Vec.val]) loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, PlanWire.children_count,
    members_count, sameView, Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]

theorem proof_correct (reference : auths_model.ProofRef) : NodeCorrect (.mk (.Proof reference)) := by
  intro self space
  have referenceLength : reference.val.length = 32 := by simpa using reference.property
  simp only [cost, viewPlan, viewNode, PlanWire.cost, byteList, List.length_map, referenceLength] at space
  rw [encode.encode_authorization_plan_to.eq_def]
  simp only [auths_model.AuthorizationPlan.as_ref, auths_model.AuthorizationPlan._0, bind_tc_ok]
  step with ProtocolWriter.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolEncoderState.u8_exact e1 0#u8 (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := encodeHead_length_le_nine ⟨0, (0#u8).val⟩
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.ProofRef.as_bytes, bind_tc_ok]
  step with UnsignedLeaves.digest_exact e3 reference (by omega) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := UnsignedLeaves.digest_length reference
  simp [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes4, bytes3, bytes2, bytes1, bytes0, viewPlan, viewNode, PlanWire.encode, UnsignedObjects.digest,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

theorem all_correct (members : alloc.vec.Vec auths_model.AuthorizationPlan)
    (correct : ElementsCorrect members.elements) : NodeCorrect (.mk (.AllOf members)) := by
  intro self space
  simp only [cost, viewPlan, viewNode, PlanWire.cost] at space
  rw [encode.encode_authorization_plan_to.eq_def]
  simp only [auths_model.AuthorizationPlan.as_ref, auths_model.AuthorizationPlan._0, bind_tc_ok]
  step with ProtocolWriter.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolEncoderState.u8_exact e1 1#u8 (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := encodeHead_length_le_nine ⟨0, (1#u8).val⟩
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with members_exact e3 members correct (by omega) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := show (UnsignedWire.array (PlanWire.encodeChildren (viewMembers members))).length ≤ 9 + PlanWire.childrenCost (viewMembers members) from Nat.le_trans (UnsignedWire.array_length _) (Nat.add_le_add_left (PlanWire.children_lengths _) 9)
  simp [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes4, bytes3, bytes2, bytes1, bytes0, viewPlan, viewNode, PlanWire.encode,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

theorem any_correct (members : alloc.vec.Vec auths_model.AuthorizationPlan)
    (correct : ElementsCorrect members.elements) : NodeCorrect (.mk (.AnyOf members)) := by
  intro self space
  simp only [cost, viewPlan, viewNode, PlanWire.cost] at space
  rw [encode.encode_authorization_plan_to.eq_def]
  simp only [auths_model.AuthorizationPlan.as_ref, auths_model.AuthorizationPlan._0, bind_tc_ok]
  step with ProtocolWriter.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolEncoderState.u8_exact e1 2#u8 (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := encodeHead_length_le_nine ⟨0, (2#u8).val⟩
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with members_exact e3 members correct (by omega) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := show (UnsignedWire.array (PlanWire.encodeChildren (viewMembers members))).length ≤ 9 + PlanWire.childrenCost (viewMembers members) from Nat.le_trans (UnsignedWire.array_length _) (Nat.add_le_add_left (PlanWire.children_lengths _) 9)
  simp [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes4, bytes3, bytes2, bytes1, bytes0, viewPlan, viewNode, PlanWire.encode,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

theorem threshold_correct (required : Std.U16) (members : alloc.vec.Vec auths_model.AuthorizationPlan)
    (correct : ElementsCorrect members.elements) : NodeCorrect (.mk (.KOfN required members)) := by
  intro self space
  simp only [cost, viewPlan, viewNode, PlanWire.cost] at space
  rw [encode.encode_authorization_plan_to.eq_def]
  simp only [auths_model.AuthorizationPlan.as_ref, auths_model.AuthorizationPlan._0, bind_tc_ok]
  step with ProtocolWriter.map_exact self 3#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 3⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolEncoderState.u8_exact e1 3#u8 (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := encodeHead_length_le_nine ⟨0, (3#u8).val⟩
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolEncoderState.u16_exact e3 required (by omega) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := encodeHead_length_le_nine ⟨0, required.val⟩
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with members_exact e5 members correct (by omega) as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := show (UnsignedWire.array (PlanWire.encodeChildren (viewMembers members))).length ≤ 9 + PlanWire.childrenCost (viewMembers members) from Nat.le_trans (UnsignedWire.array_length _) (Nat.add_le_add_left (PlanWire.children_lengths _) 9)
  simp [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, viewPlan, viewNode, PlanWire.encode,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

theorem all_nodes_correct (plan : auths_model.AuthorizationPlan) : NodeCorrect plan := by
  refine auths_model.AuthorizationPlan.rec
    (motive_1 := fun plan => NodeCorrect plan)
    (motive_2 := fun node => NodeCorrect (.mk node))
    (motive_3 := fun members => ElementsCorrect members.elements)
    (motive_4 := fun _ elements => ElementsCorrect elements)
    ?_ ?_ ?_ ?_ ?_ ?_ ?_ ?_ plan
  · intro node correct; exact correct
  · intro reference; exact proof_correct reference
  · intro members correct; exact all_correct members correct
  · intro members correct; exact any_correct members correct
  · intro required members correct; exact threshold_correct required members correct
  · intro size elements bound correct; exact correct
  · exact nil_correct
  · intro size head tail headCorrect tailCorrect
    exact cons_correct head tail headCorrect tailCorrect

@[step] theorem plan_exact (self : cbor.Encoder) (plan : auths_model.AuthorizationPlan)
    (space : self.output.val.length + cost plan ≤ Usize.max) :
    encode.encode_authorization_plan_to self plan ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ PlanWire.encode (viewPlan plan) ⦄ :=
  all_nodes_correct plan self space

@[step] theorem plan_encoder (plan : auths_model.AuthorizationPlan) (space : cost plan ≤ Usize.max) :
    encode.encode_authorization_plan plan ⦃ result => Encodes (PlanWire.encode (viewPlan plan)) result ⦄ := by
  unfold encode.encode_authorization_plan
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with plan_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) plan
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using space)
    as ⟨verdict, encoder, success, written⟩
  simp [success, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer,
    Encodes, written, alloc.vec.new_contents, byteList]

end Auths.Crypto.PlanWriters
