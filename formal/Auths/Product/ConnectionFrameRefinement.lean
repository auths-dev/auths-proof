import qualification.aeneas.generated.gateway.Funs
import Auths.Product.ConnectionFrame
import Auths.Product.Refinement.Gateway
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
namespace Auths.Product.ConnectionFrame.Refinement
open Auths.Product.Refinement.Gateway
@[step] theorem connection_preimage_exact (provider aliasBytes : Slice Std.U8)
    (providerBound : provider.val.length ≤ 64) (aliasBytesBound : aliasBytes.val.length ≤ 64) :
    identity.connection_record_preimage provider aliasBytes ⦃ output =>
      vecBytes output = ConnectionFrame.preimage ⟨sliceBytes provider, sliceBytes aliasBytes⟩ ⦄ := by
  unfold identity.connection_record_preimage
  simp only [lift, bind_tc_ok]
  apply spec_bind (copy_bytes_spec _ (by decide))
  intro prefixValue prefixEq
  apply spec_bind (append_bytes_spec _ _ (by simp only [prefixEq]; change 27 + provider.val.length < 4294967295; omega))
  intro withNamespace namespaceEq
  have pushBound : withNamespace.val.length < Usize.max := by
    apply lt_usize_max
    simp only [namespaceEq, List.length_append, prefixEq]
    change 27 + provider.val.length < 4294967295
    omega
  apply spec_bind (alloc.vec.Vec.push_spec _ _ pushBound)
  intro separated separatorEq
  apply spec_mono (append_bytes_spec _ _ (by
    simp only [separatorEq, List.length_append, List.length_singleton, namespaceEq, prefixEq]
    change 27 + provider.val.length + 1 + aliasBytes.val.length < 4294967295
    omega))
  intro output outputEq
  simp only [vecBytes, byteList, ConnectionFrame.preimage, ConnectionFrame.domain,
    outputEq, separatorEq, namespaceEq, prefixEq, List.map_append, List.map_cons,
    List.map_nil, UScalar.ofNatCore_val_eq, List.append_assoc, sliceBytes]
  rfl

end Auths.Product.ConnectionFrame.Refinement
