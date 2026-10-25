(* Captured-context regressions. Authored/unbuilt/unrun until final checks.
   Scope separation does not prove source simulation or native execution. *)
open Charon
open Types

let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ -> true
let parameter index : region_param = { index = RegionId.of_int index; name = Some "'source";
  variance = Invariant; mutability = LtShared }
let parameters regions = { TypesUtils.empty_generic_params with regions = List.map parameter regions }

let () =
  let caller = parameters [0; 1; 2; 3] in
  let shim = parameters [0; 1; 2; 3] in
  let captured = parameters [0] in
  let renamed = Vtable_specialization.fresh_capture_regions ~caller ~shim ~captured in
  require "the owner's lifetime 0 cannot capture the unrelated caller's lifetime 0"
    (renamed = [parameter 0, { (parameter 0) with index = RegionId.of_int 4 }]);
  let rename = Vtable_specialization.rename_captured_region renamed in
  require "only captured free lifetime uses are renamed"
    (rename (RVar (Free (RegionId.of_int 0))) = RVar (Free (RegionId.of_int 4)) &&
     rename (RVar (Free (RegionId.of_int 1))) = RVar (Free (RegionId.of_int 1)));
  List.iter (fun region -> require "body/local/static provenance cannot be changed by alpha-renaming"
      (rename region = region))
    [RBody (RegionId.of_int 0); RVar (Bound (0, RegionId.of_int 0));
     RVar (Bound (1, RegionId.of_int 0)); RStatic; RErased];
  let sparse = Vtable_specialization.fresh_capture_regions ~caller:(parameters [99])
    ~shim:(parameters [0; 7]) ~captured in
  require "freshening must consider both complete original parameter contexts"
    ((snd (List.hd sparse)).index = RegionId.of_int 100);
  require "duplicate original caller binders cannot enter a candidate"
    (refuses (fun () -> ignore (Vtable_specialization.fresh_capture_regions
      ~caller:(parameters [0; 0]) ~shim ~captured)));
  require "a captured lifetime absent from the source shim prefix cannot be manufactured"
    (refuses (fun () -> ignore (Vtable_specialization.fresh_capture_regions
      ~caller ~shim ~captured:(parameters [8]))));
  require "caller type variables need full cross-context renaming before captured type import"
    (refuses (fun () -> ignore (Vtable_specialization.fresh_capture_regions
      ~caller:{ caller with types = [{ index = TypeVarId.of_int 0; name = "T"; variance = Invariant }] }
      ~shim ~captured)));
  require "parameter identifier overflow cannot silently alias another binder"
    (refuses (fun () -> ignore (Vtable_specialization.fresh_capture_regions
      ~caller:(parameters [Int.max_int]) ~shim ~captured)))
