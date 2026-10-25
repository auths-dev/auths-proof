import Auths.Product.NativeUtf8KeyOrder
import Auths.Product.NativeSerdeBodyBounds
import Auths.Product.NativeCompilerSourceMapOrder

/-!
Native decoded BTreeMap order earns the complete byte-key order consumed by
the body compiler. No independent abstract order, ASCII/name validity or
source admission premise is supplied. Rust parser/BTreeMap adequacy still
must establish the original Decode relation and its ordered native maps.
-/
namespace Auths.Product.NativeSerde
open RecipeSerdeGrammar NativeCompiler

mutual
  theorem ast_order_from_carrier (input : SourceAst) (bounded : CarrierBounds (.internal .value) input) :
      NativeAstMapOrder input := by
    cases bounded with
    | internal name input fields =>
      cases input with
      | String value => exact .text value
      | Integer value => exact .integer value
      | Boolean value => exact .boolean value
      | Field name => exact .field name
      | Echo => exact .echo
      | Array values =>
          cases fields with
          | cons head tail =>
              cases head with
              | vector value children => exact .array values (ast_values_order_from_carrier children)
      | Object members =>
          cases fields with
          | cons head tail =>
              cases head with
              | map value children ordered =>
                  refine .object members ?_ (ast_members_order_from_carrier children)
                  simpa only [sourceMemberNames] using
                    NativeUtf8KeyOrder.ordered_native_keys_earn_byte_keys members.entries.val ordered
  termination_by structural bounded

  theorem ast_values_order_from_carrier {values : List SourceAst}
      (bounded : ElementsBounded (.internal .value) values) : ∀ value ∈ values, NativeAstMapOrder value := by
    cases bounded with
    | nil => simp
    | cons head tail =>
        intro value member
        rcases List.mem_cons.mp member with rfl | later
        · exact ast_order_from_carrier _ head
        · exact ast_values_order_from_carrier tail value later
  termination_by structural bounded

  theorem ast_members_order_from_carrier {members : List (String × SourceAst)}
      (bounded : MembersBounded (.internal .value) members) :
      ∀ pair ∈ members, NativeAstMapOrder pair.2 := by
    cases bounded with
    | nil => simp
    | cons fits head tail =>
        intro pair member
        rcases List.mem_cons.mp member with rfl | later
        · exact ast_order_from_carrier _ head
        · exact ast_members_order_from_carrier tail pair later
  termination_by structural bounded
end

theorem form_order_from_carrier (input : SourceForm) (bounded : CarrierBounds (.internal .form) input) :
    NativeFormMapOrder input := by
  cases bounded with
  | internal name input fields =>
    cases input with
    | String _ | Field _ | Echo => trivial
    | Json value =>
        cases fields with
        | cons head tail => exact ast_order_from_carrier value head

theorem form_members_order_from_carrier {members : List (String × SourceForm)}
    (bounded : MembersBounded (.internal .form) members) :
    ∀ pair ∈ members, NativeFormMapOrder pair.2 := by
  induction bounded with
  | nil => simp
  | cons fits head tail ih =>
      intro pair member
      rcases List.mem_cons.mp member with rfl | later
      · exact form_order_from_carrier _ head
      · exact ih pair later

theorem body_order_from_carrier (input : SourceBody) (bounded : CarrierBounds (.internal .body) input) :
    NativeBodyMapOrder input := by
  cases bounded with
  | internal name input fields =>
    cases input with
    | Json value =>
        cases fields with
        | cons head tail => exact ast_order_from_carrier value head
    | Form members =>
        cases fields with
        | cons head tail =>
            cases head with
            | map value children ordered =>
                refine ⟨?_, form_members_order_from_carrier children⟩
                simpa only [sourceMemberNames] using
                  NativeUtf8KeyOrder.ordered_native_keys_earn_byte_keys members.entries.val ordered

theorem decoded_source_earns_body_order (raw : RawJson) (input : NativeRecord .recipe)
    (original : SourceMeaning raw input) : NativeBodyMapOrder input.write.body := by
  have sourceBounds := native_decode_earns_carrier_bounds original.2
  have writeBounds := bounded_record_field sourceBounds (.record .write) input.write (by simp [recordSlots])
  have bodyBounds := bounded_record_field writeBounds (.internal .body) input.write.body (by simp [recordSlots])
  exact body_order_from_carrier input.write.body bodyBounds

end Auths.Product.NativeSerde
