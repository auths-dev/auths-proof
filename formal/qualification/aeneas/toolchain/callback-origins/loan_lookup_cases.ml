(* Direct regressions for the isolated Aeneas lookup patch. Authoring only;
   execute against the patched library in the final verification batch. The
   supplied actual LLBC provides parser/crate metadata, not a desired result. *)
open Charon
open Types
open Aeneas.Values

let require message condition = if not condition then failwith message
let refuses_duplicate action =
  try ignore (action ()); false with
  | Failure message when String.starts_with ~prefix:"Internal error, please file an issue" message -> true

let () =
  if Array.length Sys.argv <> 2 then invalid_arg "usage: loan_lookup_cases SOURCE.llbc";
  Aeneas.Config.set_backend "lean";
  Aeneas.Config.fail_hard := true;
  Aeneas.Config.warnings_as_errors := true;
  Aeneas.Config.sanity_checks := true;
  let source = match OfJson.crate_of_json_file Sys.argv.(1) with
    | Ok source -> source | Error message -> invalid_arg message in
  let span = match FunDeclId.Map.min_binding_opt source.fun_decls with
    | Some (_, definition) -> definition.item_meta.span
    | None -> invalid_arg "the actual source has no function span" in
  let crate = { source with declarations = []; type_decls = TypeDeclId.Map.empty;
    fun_decls = FunDeclId.Map.empty; global_decls = GlobalDeclId.Map.empty;
    trait_decls = TraitDeclId.Map.empty; trait_impls = TraitImplId.Map.empty } in
  let context = Aeneas.InterpUtils.initialize_eval_ctx (Some span)
    (Aeneas.Interp.compute_contexts crate) [] [] [] Aeneas.ContextsBase.empty_marked_ids in
  let target = SymbolicValueId.of_int 7 in
  let ty = TRef (RVar (Free (RegionId.of_int 0)), TLiteral (TUInt U64), RMut) in
  let meta : mconsumed_symb = { sv_id = SymbolicValueId.of_int 100; proj_ty = ty } in
  let a_projector id : symbolic_proj = { sv_id = SymbolicValueId.of_int id; proj_ty = ty } in
  let e_projector id : esymbolic_proj = { sv_id = SymbolicValueId.of_int id; proj_ty = ty } in
  let a_loan : aproj_loans = { proj = a_projector 7; consumed = []; borrows = [] } in
  let e_loan : eproj_loans = { proj = e_projector 7; consumed = []; borrows = [] } in
  let a_leaf = AProjLoans a_loan and e_leaf = EProjLoans e_loan in
  let a_wrap child = AProjBorrows { proj = a_projector 99; loans = [meta, child] } in
  let e_wrap child = EProjBorrows { proj = e_projector 99; loans = [meta, child] } in
  let given_back : symbolic_value = { sv_id = SymbolicValueId.of_int 101; sv_ty = ty } in
  let ended_meta : ended_proj_borrow_meta = { consumed = SymbolicValueId.of_int 100; given_back } in
  let a_wrappers = [a_wrap;
    (fun child -> AEndedProjLoans { proj = SymbolicValueId.of_int 99; consumed = [meta, child]; borrows = [] });
    (fun child -> AEndedProjBorrows { mvalues = ended_meta; loans = [meta, child] })] in
  let e_wrappers = [e_wrap;
    (fun child -> EEndedProjLoans { proj = SymbolicValueId.of_int 99; consumed = [meta, child]; borrows = [] });
    (fun child -> EEndedProjBorrows { mvalues = ended_meta; loans = [meta, child] })] in
  let abstraction id avalues cont : abs = { abs_id = AbsId.of_int id;
    kind = SynthInput (RegionGroupId.of_int 0); can_end = false;
    parents = AbsId.Set.empty; regions = { owned = RegionId.Set.singleton (RegionId.of_int 0) };
    ended_subabs = AbsLevelSet.empty;
    avalues = List.map (fun projector -> ({ value = ASymbolic (PNone, projector); ty } : tavalue)) avalues;
    cont } in
  let e_value projector : tevalue = { value = ESymbolic (PNone, projector); ty } in
  let continuation input output : abs_cont = { input = Option.map e_value input; output = Option.map e_value output } in
  let lookup environments = Aeneas.InterpBorrowsCore.lookup_aproj_loans_opt span
    (AbsId.of_int 3) target { context with env = List.map (fun abs -> EAbs abs) environments } in
  require "an absent projector remains absent"
    (lookup [abstraction 3 [AEmpty] None] = None);
  List.iter (fun wrap ->
    let nested = List.fold_left (fun child _ -> wrap child) a_leaf [0; 1; 2; 3] in
    require "one nested actual loan projector must be visited exactly once"
      (lookup [abstraction 3 [nested] None] = Some (a_loan, None));
    require "two actual occurrences of the very same loan record must still refuse"
      (refuses_duplicate (fun () -> lookup [abstraction 3 [wrap a_leaf; wrap a_leaf] None]))
  ) a_wrappers;
  List.iter (fun wrap ->
    let nested = List.fold_left (fun child _ -> wrap child) e_leaf [0; 1; 2; 3] in
    require "one nested continuation projector must be visited exactly once"
      (lookup [abstraction 3 [a_leaf] (Some (continuation None (Some nested)))] = Some (a_loan, Some e_loan));
    require "two actual continuation projector occurrences must still refuse"
      (refuses_duplicate (fun () -> lookup [abstraction 3 [a_leaf]
        (Some (continuation (Some (wrap e_leaf)) (Some (wrap e_leaf))))]))
  ) e_wrappers;
  require "another abstraction cannot supply or duplicate this abstraction's projector"
    (lookup [abstraction 4 [a_leaf; a_leaf] None; abstraction 3 [a_wrap a_leaf] None] = Some (a_loan, None));
  require "two direct occurrences remain invalid without a wrapping node"
    (refuses_duplicate (fun () -> lookup [abstraction 3 [a_leaf; a_leaf] None]))
