(* Capture closure regressions. Authored/unbuilt/unrun until final checks. *)
open Charon
open Types

let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ -> true
let empty = TypesUtils.empty_generic_args
let boolean = TLiteral Charon.Values.TBool
let region id : region_param = { index = RegionId.of_int id; name = None;
  variance = Invariant; mutability = LtShared }
let type_id = TypeVarId.of_int 5
let const_id = ConstGenericVarId.of_int 8
let clause_id = TraitClauseId.of_int 9
let usize = TLiteral (Charon.Values.TUInt Charon.Values.Usize)
let predicate depth = { binder_regions = []; binder_value = { id = TraitDeclId.of_int 4;
  generics = { empty with types = [TVar (Bound (depth, type_id))] } } }
let parameters = { TypesUtils.empty_generic_params with
  types = [{ index = type_id; name = "T"; variance = Invariant }];
  const_generics = [{ index = const_id; name = "SIZE"; ty = usize }];
  trait_clauses = [{ clause_id; span = None; origin = OriginDyn; trait = predicate 1 }] }
let arguments = { empty with types = [TVar (Bound (0, type_id))];
  const_generics = [{ kind = CVar (Bound (0, const_id)); ty = usize }];
  trait_refs = [{ kind = Clause (Bound (0, clause_id)); trait_decl_ref = predicate 1 }] }

let () =
  Closed_arguments.require ~parameters:[region 3] { empty with types = [TRef (RVar (Free (RegionId.of_int 3)), boolean, RShared)] };
  List.iter (fun arguments -> require "unresolved caller placeholders are not closed native captures"
      (refuses (fun () -> Closed_arguments.require ~parameters:[] arguments)))
    [{ empty with types = [TVar (Free type_id)] };
     { empty with const_generics = [{ kind = CVar (Free const_id); ty = usize }] };
     { empty with trait_refs = [{ kind = Clause (Free clause_id); trait_decl_ref = predicate 1 }] };
     { empty with trait_refs = [{ kind = Self; trait_decl_ref = predicate 1 }] };
     { empty with const_generics = [{ kind = COpaque "missing source value"; ty = usize }] };
     { empty with regions = [RBody (RegionId.of_int 0)] }];
  let check = new Closed_arguments.check [] in
  check#visit_binder check#visit_generic_args [] { binder_params = parameters; binder_value = arguments };
  require "an empty region binder still counts for nested type/dictionary depth"
    (refuses (fun () -> check#visit_binder check#visit_generic_args [] {
      binder_params = parameters; binder_value = { arguments with trait_refs = [
        { kind = Clause (Bound (0, clause_id)); trait_decl_ref = predicate 0 }] } })));
  require "a quantified source type cannot escape its original binder"
    (refuses (fun () -> Closed_arguments.require ~parameters:[] { empty with types = [TVar (Bound (0, type_id))] })));
  require "duplicate quantified type parameters cannot create a closed-capture witness"
    (refuses (fun () -> check#visit_binder check#visit_generic_args [] { binder_params = {
      parameters with types = parameters.types @ parameters.types }; binder_value = arguments }));
  let executable = new Closed_arguments.statement_check ~body_regions:1 [] in
  executable#visit_ty [] (TRef (RBody (RegionId.of_int 0), boolean, RShared));
  require "executable body provenance must still stay inside the original body region binder"
    (refuses (fun () -> executable#visit_ty [] (TRef (RBody (RegionId.of_int 1), boolean, RShared))))
