(* Source-lifetime witness regressions. Authored only; defer execution to the
   final validation batch. These synthetic declarations do not qualify Rust. *)
open Charon
open Types
open Values

let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ -> true
let empty = TypesUtils.empty_generic_args
let boolean = TLiteral TBool
let free = RVar (Free (RegionId.of_int 0))
let reference region = TRef (region, boolean, RShared)
let normalize ty = ty
let location : Meta.loc = { line = 1; col = 0 }
let span : Meta.span = { data = {
  file = { name = Meta.NotReal "closed-source-type-fixture";
    crate_name = "construction_fixture"; contents = None };
  beg_loc = location; end_loc = location }; generated_from_span = None }
let attributes : Meta.attr_info = { attributes = []; inline = None; rename = None; public = true }
let metadata : item_meta = { name = []; span; source_text = None; attr_info = attributes;
  is_local = true; opacity = Transparent; lang_item = None }
let id = TypeDeclId.of_int 7
let declaration kind : type_decl = { def_id = id; item_meta = metadata;
  generics = TypesUtils.empty_generic_params; src = TopLevelItem; kind;
  layout = []; ptr_metadata = NoMetadata }
let nominal = TAdt { id = TAdtId id; generics = empty }
let create declarations = Closed_type.create ~declarations ~normalize

let () =
  let no_types = TypeDeclId.Map.empty in
  let proof = create no_types boolean in
  require "literal lifetime evidence must replay from the same type"
    (Closed_type.replay ~declarations:no_types ~normalize proof);
  ignore (create no_types (reference RStatic));
  List.iter (fun region ->
    require "borrow lifetime evidence cannot be guessed or strengthened"
      (refuses (fun () -> ignore (create no_types (reference region)))))
    [free; RErased; RBody (RegionId.of_int 9); RVar (Bound (0, RegionId.of_int 0))];
  require "missing nominal declarations are not evidence"
    (refuses (fun () -> ignore (create no_types nominal)));
  let types = TypeDeclId.Map.singleton id (declaration (Alias boolean)) in
  let witness = create types nominal in
  require "a nominal witness must inspect the instantiated source representation"
    (match witness.nominal with Some source -> source.source_kind = Alias boolean | None -> false);
  require "changing the source representation must invalidate its old lifetime witness"
    (not (Closed_type.replay ~normalize witness
      ~declarations:(TypeDeclId.Map.singleton id (declaration (Alias (reference free))))));
  List.iter (fun kind -> require "unsupported source representations cannot stand in for closed lifetime evidence"
    (refuses (fun () -> ignore (create (TypeDeclId.Map.singleton id (declaration kind)) nominal))))
    [Opaque; TDeclError "fixture extraction failure"; Alias nominal; Alias (reference RErased)];
  let source = { (declaration (Alias (TVar (Free (TypeVarId.of_int 0))))) with
    generics = { TypesUtils.empty_generic_params with types = [
      { index = TypeVarId.of_int 0; name = "T"; variance = Invariant }] } } in
  let types = TypeDeclId.Map.singleton id source in
  let instantiate ty = TAdt { id = TAdtId id; generics = { empty with types = [ty] } } in
  ignore (create types (instantiate boolean));
  require "a generic source alias must preserve borrowed argument lifetime provenance"
    (refuses (fun () -> ignore (create types (instantiate (reference free)))));
  require "a nominal argument arity mismatch cannot be silently filled"
    (refuses (fun () -> ignore (create types nominal)));
  let replay = Static_targets.replay_outlives ~declarations:no_types ~normalize in
  let unbound value = { binder_regions = []; binder_value = value } in
  require "the static region can outlive a concrete caller parameter"
    (replay (Static_targets.StaticRegion (unbound (RStatic, free))));
  require "an outlives witness cannot claim that a borrowed parameter is static"
    (not (replay (Static_targets.StaticRegion (unbound (free, RStatic)))));
  require "a body region cannot masquerade as source lifetime provenance"
    (not (replay (Static_targets.ReflexiveRegion (unbound (RBody (RegionId.of_int 4), RBody (RegionId.of_int 4))))));
  require "a closed type witness must be attached to its exact source type"
    (not (replay (Static_targets.ClosedSourceType (unbound (reference free, RStatic), proof))));
  require "an unbound quantified target cannot be invented"
    (not (replay (Static_targets.ClosedSourceType
      (unbound (boolean, RVar (Bound (0, RegionId.of_int 0)))), proof))))
