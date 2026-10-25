open Aeneas
open Types
open Values

let require message condition = if not condition then failwith message

let () =
  let rid = RegionId.of_int 0 in
  let bool_ty = TLiteral TBool in
  let char_ty = TLiteral TChar in
  let shared region ty = TRef (region, ty, RShared) in
  let erased = shared RErased bool_ty in
  let regions = [ RStatic; RBody rid; RVar (Free rid); RVar (Bound (0, rid)); RErased ] in
  List.iter
    (fun region ->
      let input = shared region bool_ty in
      require "every runtime region must be erased"
        (Substitute.erase_regions input = erased);
      require "erasure must agree with Aeneas' existing full-type eraser"
        (Substitute.erase_regions input = TypesUtils.ty_erase_regions input);
      require "erasure must be idempotent"
        (Substitute.erase_regions (Substitute.erase_regions input) = erased))
    regions;
  require "reference mutability must remain significant"
    (Substitute.erase_regions (TRef (RStatic, bool_ty, RMut)) <> erased);
  require "pointee type must remain significant"
    (Substitute.erase_regions (shared RStatic char_ty) <> erased);
  let nested = TAdt {
    id = TTuple;
    generics = { TypesUtils.empty_generic_args with
      regions = [ RStatic; RBody rid ];
      types = [ shared RStatic (shared (RVar (Free rid)) bool_ty) ] }
  } in
  require "nested regions and generic arguments must all be erased"
    (Substitute.erase_regions nested = TypesUtils.ty_erase_regions nested);
  let generics = { TypesUtils.empty_generic_args with regions = [ RStatic ] } in
  require "generic signature substitution must retain static regions"
    ((Substitute.generic_args_erase_regions generics).regions = [ RStatic ]);
  require "global-reference instantiation must retain static regions"
    (Substitute.erase_regions_substitute_types Substitute.empty_subst
       (shared RStatic bool_ty) = shared RStatic bool_ty);
  require "ordinary regionful substitution must retain static regions"
    (Substitute.ty_substitute Substitute.empty_subst (shared RStatic bool_ty)
      = shared RStatic bool_ty)
