import qualification.aeneas.generated.codec.FunsExternal
import Auths.Model.IdentifierString
open Aeneas Aeneas.Std Result
namespace Auths.Codec.StringRefinement

theorem byte_array_round_trip (value : String)
    (bounded : value.toByteArray.size ≤ U32.max) :
    Auths.Codec.StdModel.bytes (toStr value bounded) = value.toByteArray := by
  apply ByteArray.ext
  apply _root_.Array.toList_inj.mp
  unfold Auths.Codec.StdModel.bytes toStr
  simp only [List.toList_data_toByteArray, List.map_map]
  rw [← Auths.Model.Identifier.byte_array_list]
  change value.toByteArray.toList.map (fun byte => UInt8.ofNat byte.toNat) =
    value.toByteArray.toList
  simp only [UInt8.ofNat_toNat, List.map_id']

theorem string_copy_exact (value : String)
    (bounded : value.toByteArray.size ≤ U32.max) :
    alloc.string.String.Insts.CoreConvertFromShared0Str.from (toStr value bounded) = ok value := by
  unfold alloc.string.String.Insts.CoreConvertFromShared0Str.from
  rw [byte_array_round_trip]
  simp only [String.fromUTF8?, dif_pos value.isValidUTF8]
  rfl

theorem string_borrow_exact (value : String)
    (bounded : value.toByteArray.size ≤ U32.max) :
    alloc.string.String.Insts.CoreOpsDerefDerefStr.deref value = ok (toStr value bounded) := by
  simp only [alloc.string.String.Insts.CoreOpsDerefDerefStr.deref, dif_pos bounded]

theorem utf8_accepts_string (value : String)
    (bounded : value.toByteArray.size ≤ U32.max) :
    core.str.converts.from_utf8 (toStr value bounded) = ok (.Ok (toStr value bounded)) := by
  simp only [core.str.converts.from_utf8, byte_array_round_trip,
    if_pos value.isValidUTF8]

end Auths.Codec.StringRefinement
