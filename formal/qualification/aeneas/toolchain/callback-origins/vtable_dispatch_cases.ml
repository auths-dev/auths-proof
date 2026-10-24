(* Pairing/path regressions. These construct source paths only, not a native
   dispatch proof. All cases remain unbuilt/unrun until final validation. *)
open Charon
open Types
open Expressions
open LlbcAst

let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ -> true
let empty = TypesUtils.empty_generic_args
let boolean = TLiteral Charon.Values.TBool
let reference : type_decl_ref = { id = TAdtId (TypeDeclId.of_int 7); generics = empty }
let table = TAdt reference
let receiver index : place = { kind = PlaceLocal (LocalId.of_int index);
  ty = TRef (RVar (Free (RegionId.of_int 0)), boolean, RShared) }
let metadata parent ty : place = { kind = PlaceProjection (parent, PtrMetadata); ty }
let deref metadata : place = { kind = PlaceProjection (metadata, Deref); ty = table }
let signature : fun_sig region_binder = { binder_regions = []; binder_value = {
  is_unsafe = false; abi = AbiRust; is_variadic = false; inputs = [(receiver 1).ty]; output = boolean } }
let field meta id ty : place = { kind = PlaceProjection (deref meta,
  Field (ProjAdt (TypeDeclId.of_int id, None), FieldId.of_int 3)); ty }
let original_metadata = metadata (receiver 1) (TRawPtr (table, RShared))
let original_function = field original_metadata 7 (TFnPtr signature)
let call function_place argument : call = { func = FnOpDynamic (Copy function_place);
  args = [Move argument]; dest = { kind = PlaceLocal (LocalId.of_int 0); ty = boolean } }

let () =
  let function_place, actual_metadata, actual_receiver, actual_table, actual_field =
    Vtable_dispatch.lookup_path (call original_function (receiver 1)) in
  require "the parser must retain the complete original paired place and nominal field path"
    (function_place = original_function && actual_metadata = original_metadata &&
     actual_receiver = receiver 1 && actual_table = reference && actual_field = FieldId.of_int 3);
  require "metadata from another receiver cannot dispatch this receiver even when the types match"
    (refuses (fun () -> ignore (Vtable_dispatch.lookup_path (call original_function (receiver 2)))));
  require "the nominal table and field projection IDs must agree"
    (refuses (fun () -> ignore (Vtable_dispatch.lookup_path
      (call (field original_metadata 8 (TFnPtr signature)) (receiver 1)))));
  require "a non-function value cannot be relabelled as a vtable method"
    (refuses (fun () -> ignore (Vtable_dispatch.lookup_path
      (call (field original_metadata 7 boolean) (receiver 1)))));
  require "the original raw metadata pointee cannot be changed to another table"
    (let other = TAdt { reference with id = TAdtId (TypeDeclId.of_int 8) } in
      refuses (fun () -> ignore (Vtable_dispatch.lookup_path
        (call (field (metadata (receiver 1) (TRawPtr (other, RShared))) 7 (TFnPtr signature)) (receiver 1)))));
  require "the source lookup's pointer representation cannot be silently converted"
    (refuses (fun () -> ignore (Vtable_dispatch.lookup_path
      (call (field (metadata (receiver 1) (TRef (RStatic, table, RShared))) 7 (TFnPtr signature)) (receiver 1)))));
  require "a source constant function result cannot replace the actual field operand"
    (refuses (fun () -> ignore (Vtable_dispatch.lookup_path { (call original_function (receiver 1)) with
      func = FnOpDynamic (Constant { kind = COpaque "unmodeled function value"; ty = TFnPtr signature }) })))
