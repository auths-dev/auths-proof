import Auths.Crypto.BundleSelectors
import Auths.Codec.RecordNormalization

open Aeneas Aeneas.Std Result
open AuthsProtocolCodec

namespace Auths.Crypto.BundleSorting
open Auths.Codec

/- The three actual borrowed-record key sorts use the same reviewed stable
standard-key interface as owned normalization. Their real selectors and real
identifier comparison dictionaries are supplied by proved source leaves, not
caller assumptions. Complete payloads survive key ties. Identifier derivation
and the complete bundle writer still require their own source composition. -/
theorem grant_keys_exact
    (values : alloc.vec.Vec (auths_model.GrantId × auths_model.SignedGrant)) :
    encode.sort_grant_ref_keys values =
      ok (SnapshotOrdering.sortedByKey RecordNormalization.grantKey values) := by
  auths_record_key_sort encode.sort_grant_ref_keys,
    encode.grant_ref_sort_key, BundleSelectors.grant_key,
    ProtocolOrdering.grantIdKey, ProtocolOrdering.grant_id_compare, RecordNormalization.grantKey

theorem principal_status_keys_exact
    (values : alloc.vec.Vec (auths_model.PrincipalStatusId × auths_model.SignedPrincipalStatus)) :
    encode.sort_principal_status_ref_keys values =
      ok (SnapshotOrdering.sortedByKey RecordNormalization.principalStatusKey values) := by
  auths_record_key_sort encode.sort_principal_status_ref_keys,
    encode.principal_status_ref_sort_key, BundleSelectors.principal_status_key,
    ProtocolOrdering.principalStatusIdKey, ProtocolOrdering.principal_status_id_compare,
    RecordNormalization.principalStatusKey

theorem grant_status_keys_exact
    (values : alloc.vec.Vec (auths_model.GrantStatusId × auths_model.SignedGrantStatus)) :
    encode.sort_grant_status_ref_keys values =
      ok (SnapshotOrdering.sortedByKey RecordNormalization.grantStatusKey values) := by
  auths_record_key_sort encode.sort_grant_status_ref_keys,
    encode.grant_status_ref_sort_key, BundleSelectors.grant_status_key,
    ProtocolOrdering.grantStatusIdKey, ProtocolOrdering.grant_status_id_compare,
    RecordNormalization.grantStatusKey

end Auths.Crypto.BundleSorting
