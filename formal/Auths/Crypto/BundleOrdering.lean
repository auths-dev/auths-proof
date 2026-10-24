import Auths.Crypto.BundleObjects
import Auths.Codec.ProtocolOrdering

open Aeneas Aeneas.Std Result
open AuthsProtocolCodec

namespace Auths.Crypto.BundleOrdering
open Auths.Codec

/- Concrete source Ord dictionaries, not caller-supplied comparison laws.
The byte key representation is injective for IDs; no statement-to-ID hash
injectivity is used or inferred. Statement references order by variant and
then every identifier byte, as independently specified by statementKey. -/
theorem proof_ref_compare (left right : auths_model.ProofRef) :
    auths_model.ProofRef.Insts.CoreCmpOrd.cmp left right =
      ok (compare (ProtocolOrdering.digestKey left) (ProtocolOrdering.digestKey right)) := by
  simp only [auths_model.ProofRef.Insts.CoreCmpOrd.cmp, auths_model.Digest.Insts.CoreCmpOrd.cmp]
  rw [Auths.Composition.Order.array_comparison, Auths.Composition.Order.bytes_comparison,
    ProtocolOrdering.list_comparison]

theorem evidence_id_compare (left right : auths_model.EvidenceId) :
    auths_model.EvidenceId.Insts.CoreCmpOrd.cmp left right =
      ok (compare (ProtocolOrdering.digestKey left) (ProtocolOrdering.digestKey right)) := by
  simp only [auths_model.EvidenceId.Insts.CoreCmpOrd.cmp, auths_model.Digest.Insts.CoreCmpOrd.cmp]
  rw [Auths.Composition.Order.array_comparison, Auths.Composition.Order.bytes_comparison,
    ProtocolOrdering.list_comparison]

theorem attachment_digest_compare (left right : auths_model.AttachmentDigest) :
    auths_model.AttachmentDigest.Insts.CoreCmpOrd.cmp left right =
      ok (compare (ProtocolOrdering.digestKey left) (ProtocolOrdering.digestKey right)) := by
  simp only [auths_model.AttachmentDigest.Insts.CoreCmpOrd.cmp, auths_model.Digest.Insts.CoreCmpOrd.cmp]
  rw [Auths.Composition.Order.array_comparison, Auths.Composition.Order.bytes_comparison,
    ProtocolOrdering.list_comparison]

theorem statement_compare (left right : auths_model.StatementRef) :
    auths_model.StatementRef.Insts.CoreCmpOrd.cmp left right =
      ok (compare (BundleObjects.statementKey left) (BundleObjects.statementKey right)) := by
  rw [← ProtocolOrdering.list_comparison]
  cases left <;> cases right <;>
    simp [auths_model.StatementRef.Insts.CoreCmpOrd.cmp,
      BundleObjects.statementKey, BundleObjects.statementParts, byteList,
      ProtocolOrdering.grant_id_compare, ProtocolOrdering.principal_status_id_compare,
      ProtocolOrdering.grant_status_id_compare, auths_model.ActionId.Insts.CoreCmpOrd.cmp,
      ProtocolOrdering.digest_compare, ProtocolOrdering.digestKey,
      ProtocolOrdering.grantIdKey, ProtocolOrdering.principalStatusIdKey,
      ProtocolOrdering.grantStatusIdKey, List.compareLex, bind_tc_ok]
  all_goals first | rfl | scalar_tac

end Auths.Crypto.BundleOrdering
