import Auths.Crypto.BundleOrdering
import Auths.Crypto.BundleSelectors
import Auths.Codec.RecordNormalization

open Aeneas Aeneas.Std Result
open AuthsProtocolCodec

namespace Auths.Crypto.BundleFieldSorting
open Auths.Codec

theorem field_relation {Value NativeKey Key : Type} [LinearOrder Key]
    (field : Value → NativeKey) (view : NativeKey → Key) :
    ProtocolSort.keyedRelation field (fun left right => compare (view left) (view right)) =
      StableNormalization.before (fun value => view (field value)) := by
  funext left right
  exact propext (SnapshotOrdering.compare_is_le _ _)

syntax "auths_bundle_field_sort " term "," term "," term "," term "," term "," term "," term : tactic
macro_rules
| `(tactic| auths_bundle_field_sort $source, $selector, $selectorLaw, $projected, $view, $comparisonLaw, $entryKey) =>
  `(tactic|
    (unfold $source
     simp only [core.ops.deref.DerefMutVec, alloc.vec.Vec.deref_mut, bind_tc_ok]
     rw [ProtocolSort.slice_keyed_sort_exact _ _ _ $projected
       (fun left right => compare ($view left) ($view right)) (by
         intro value
         change (do let identifier ← $selector value
                    ok (identifier, _)) = _
         rw [$selectorLaw]
         rfl) $comparisonLaw]
     simp only [bind_tc_ok]
     congr 1
     apply alloc.vec.contents_injective
     simp [Aeneas.Std.alloc.vec.Vec.deref_mut, alloc.vec.Vec.ofBase,
       alloc.vec.Vec.toBase, alloc.vec.Vec.val,
       auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.Vec.toBase,
       auths_composition.alloc.vec.Vec.val, auths_composition.alloc.vec.SizedList.toList_ofList,
       SnapshotOrdering.sortedByKey, StableNormalization.sort, field_relation, $entryKey,
       BundleObjects.digestKey, ProtocolOrdering.digestKey, Auths.Codec.Refinement.byteList]))

theorem actions_exact (values : alloc.vec.Vec auths_model.SignedAction) :
    encode.sort_action_refs values = ok (SnapshotOrdering.sortedByKey BundleObjects.actionKey values) := by
  auths_bundle_field_sort encode.sort_action_refs, encode.action_ref_sort_key, BundleSelectors.action_key,
    (fun value : auths_model.SignedAction => value.envelope.proof_ref),
    ProtocolOrdering.digestKey, BundleOrdering.proof_ref_compare, BundleObjects.actionKey

theorem evidence_exact (values : alloc.vec.Vec auths_model.EvidenceObject) :
    encode.sort_evidence_refs values = ok (SnapshotOrdering.sortedByKey BundleObjects.evidenceKey values) := by
  auths_bundle_field_sort encode.sort_evidence_refs, encode.evidence_ref_sort_key, BundleSelectors.evidence_key,
    (fun value : auths_model.EvidenceObject => value.id),
    ProtocolOrdering.digestKey, BundleOrdering.evidence_id_compare, BundleObjects.evidenceKey

theorem bindings_exact (values : alloc.vec.Vec auths_model.ControlBinding) :
    encode.sort_binding_refs values = ok (SnapshotOrdering.sortedByKey BundleObjects.bindingKey values) := by
  auths_bundle_field_sort encode.sort_binding_refs, encode.binding_ref_sort_key, BundleSelectors.binding_key,
    (fun value : auths_model.ControlBinding => value.statement),
    BundleObjects.statementKey, BundleOrdering.statement_compare, BundleObjects.bindingKey

theorem attachments_exact (values : alloc.vec.Vec auths_model.AttachmentDescriptor) :
    encode.sort_attachment_refs values = ok (SnapshotOrdering.sortedByKey BundleObjects.attachmentKey values) := by
  auths_bundle_field_sort encode.sort_attachment_refs, encode.attachment_ref_sort_key, BundleSelectors.attachment_key,
    (fun value : auths_model.AttachmentDescriptor => value.digest),
    ProtocolOrdering.digestKey, BundleOrdering.attachment_digest_compare, BundleObjects.attachmentKey

end Auths.Crypto.BundleFieldSorting
