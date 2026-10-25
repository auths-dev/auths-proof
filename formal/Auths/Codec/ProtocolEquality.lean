import Auths.Codec.ProtocolCollectionScans
import Auths.Verifier.StatusGrantLeaves
import Mathlib.Data.Prod.Lex

open Aeneas Aeneas.Std Result
open AuthsProtocolCodec

namespace Auths.Codec.ProtocolEquality

/- Concrete source equalities discharge generic collection-scan laws. These
equations concern representation equality. They do not assert hash injectivity,
signature validity or equal authority for different representations. -/

theorem principal_exact (left right : auths_model.PrincipalId) :
    auths_model.PrincipalId.Insts.CoreCmpPartialEqPrincipalId.eq left right =
      ok (decide (left = right)) := by
  simp [auths_model.PrincipalId.Insts.CoreCmpPartialEqPrincipalId.eq,
    AuthsProtocolCodec.alloc.string.String.Insts.CoreCmpPartialEqString.eq,
    _root_.alloc.string.String.Insts.CoreCmpPartialEqString.eq]

theorem audience_exact (left right : auths_model.Audience) :
    auths_model.Audience.Insts.CoreCmpPartialEqAudience.eq left right =
      ok (decide (left = right)) := by
  simp [auths_model.Audience.Insts.CoreCmpPartialEqAudience.eq,
    AuthsProtocolCodec.alloc.string.String.Insts.CoreCmpPartialEqString.eq,
    _root_.alloc.string.String.Insts.CoreCmpPartialEqString.eq]

theorem extension_id_exact (left right : auths_model.ExtensionId) :
    auths_model.ExtensionId.Insts.CoreCmpPartialEqExtensionId.eq left right =
      ok (decide (left = right)) := by
  simp [auths_model.ExtensionId.Insts.CoreCmpPartialEqExtensionId.eq,
    AuthsProtocolCodec.alloc.string.String.Insts.CoreCmpPartialEqString.eq,
    _root_.alloc.string.String.Insts.CoreCmpPartialEqString.eq]

theorem fact_name_exact (left right : auths_model.observation.FactName) :
    auths_model.observation.FactName.Insts.CoreCmpPartialEqFactName.eq left right =
      ok (decide (left = right)) := by
  simp [auths_model.observation.FactName.Insts.CoreCmpPartialEqFactName.eq,
    AuthsProtocolCodec.alloc.string.String.Insts.CoreCmpPartialEqString.eq,
    _root_.alloc.string.String.Insts.CoreCmpPartialEqString.eq]

theorem digest_exact (left right : auths_model.Digest) :
    auths_model.Digest.Insts.CoreCmpPartialEqDigest.eq left right = ok (decide (left = right)) := by
  simp [auths_model.Digest.Insts.CoreCmpPartialEqDigest.eq,
    Auths.StatusSelection.byte_array_comparison]

theorem evidence_id_exact (left right : auths_model.EvidenceId) :
    auths_model.EvidenceId.Insts.CoreCmpPartialEqEvidenceId.eq left right =
      ok (decide (left = right)) := by
  simp [auths_model.EvidenceId.Insts.CoreCmpPartialEqEvidenceId.eq, digest_exact]

theorem approval_digest_exact (left right : auths_model.ApprovalDigest) :
    auths_model.ApprovalDigest.Insts.CoreCmpPartialEqApprovalDigest.eq left right =
      ok (decide (left = right)) := by
  simp [auths_model.ApprovalDigest.Insts.CoreCmpPartialEqApprovalDigest.eq, digest_exact]

def permissionView (value : auths_model.Permission) : String ×ₗ String :=
  toLex (value.capability, value.resource)

theorem permission_view_injective : Function.Injective permissionView := by
  intro left right same
  cases left
  cases right
  simpa [permissionView] using same

theorem permission_exact (left right : auths_model.Permission) :
    auths_model.Permission.Insts.CoreCmpPartialEqPermission.eq left right =
      ok (decide (permissionView left = permissionView right)) := by
  simp [auths_model.Permission.Insts.CoreCmpPartialEqPermission.eq,
    auths_model.CapabilityId.Insts.CoreCmpPartialEqCapabilityId.eq,
    auths_model.ResourceId.Insts.CoreCmpPartialEqResourceId.eq,
    AuthsProtocolCodec.alloc.string.String.Insts.CoreCmpPartialEqString.eq,
    _root_.alloc.string.String.Insts.CoreCmpPartialEqString.eq, permissionView]

theorem audiences_scan_exact (values : Slice auths_model.Audience) :
    @auths_model.collection_scan.adjacent_equal auths_model.Audience
      auths_model.Audience.Insts.CoreCmpPartialEqAudience values =
      ok (CollectionInvariants.adjacent values.val) := by
  simpa using ProtocolCollectionScans.adjacent_exact
    auths_model.Audience.Insts.CoreCmpPartialEqAudience id
    (by intro left right; exact audience_exact left right) values

theorem principals_scan_exact (values : Slice auths_model.PrincipalId) :
    @auths_model.collection_scan.adjacent_equal auths_model.PrincipalId
      auths_model.PrincipalId.Insts.CoreCmpPartialEqPrincipalId values =
      ok (CollectionInvariants.adjacent values.val) := by
  simpa using ProtocolCollectionScans.adjacent_exact
    auths_model.PrincipalId.Insts.CoreCmpPartialEqPrincipalId id
    (by intro left right; exact principal_exact left right) values

theorem body_digests_scan_exact (values : Slice auths_model.Digest) :
    @auths_model.collection_scan.adjacent_equal auths_model.Digest
      auths_model.Digest.Insts.CoreCmpPartialEqDigest values =
      ok (CollectionInvariants.adjacent values.val) := by
  simpa using ProtocolCollectionScans.adjacent_exact
    auths_model.Digest.Insts.CoreCmpPartialEqDigest id
    (by intro left right; exact digest_exact left right) values

theorem permissions_scan_exact (values : Slice auths_model.Permission) :
    @auths_model.collection_scan.adjacent_equal auths_model.Permission
      auths_model.Permission.Insts.CoreCmpPartialEqPermission values =
      ok (CollectionInvariants.adjacent (values.val.map permissionView)) :=
  ProtocolCollectionScans.adjacent_exact auths_model.Permission.Insts.CoreCmpPartialEqPermission
    permissionView (by intro left right; exact permission_exact left right) values

theorem binding_ids_scan_exact (values : Slice auths_model.EvidenceId) :
    @auths_model.collection_scan.adjacent_equal auths_model.EvidenceId
      auths_model.EvidenceId.Insts.CoreCmpPartialEqEvidenceId values =
      ok (CollectionInvariants.adjacent values.val) := by
  simpa using ProtocolCollectionScans.adjacent_exact
    auths_model.EvidenceId.Insts.CoreCmpPartialEqEvidenceId id
    (by intro left right; exact evidence_id_exact left right) values

theorem approval_ids_scan_exact (values : Slice auths_model.ApprovalDigest) :
    @auths_model.collection_scan.adjacent_equal auths_model.ApprovalDigest
      auths_model.ApprovalDigest.Insts.CoreCmpPartialEqApprovalDigest values =
      ok (CollectionInvariants.adjacent values.val) := by
  simpa using ProtocolCollectionScans.adjacent_exact
    auths_model.ApprovalDigest.Insts.CoreCmpPartialEqApprovalDigest id
    (by intro left right; exact approval_digest_exact left right) values

end Auths.Codec.ProtocolEquality
