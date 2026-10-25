(* Scope separation regressions, authored/unbuilt/unrun for the final batch. *)
open Charon.Types
let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ -> true
let parameter index : region_param = { index = RegionId.of_int index; name = None; variance = Invariant; mutability = LtUnknown }
let body index = RBody (RegionId.of_int index)
let free index = RVar (Free (RegionId.of_int index))
let make ?(source_parameters = [parameter 7]) ?(source_body_regions = 4)
    ?(caller_parameters = [parameter 11]) ?(caller_body_regions = 4)
    ?(actual_arguments = [body 3]) environment =
  Capture_scope.create ~source_parameters ~source_body_regions ~caller_parameters ~caller_body_regions
    ~actual_arguments ~environment ~constraints:Region_equations.empty_predicates

let () =
  let scope = make [free 7; body 3; body 3; RStatic] in
  require "equal numeric body IDs in different scopes cannot identify the same lifetime"
    (List.map (fun (binding : Capture_scope.binding) -> binding.label) scope.bindings =
      [Capture_scope.Caller (body 3); Capture_scope.Private (RegionId.of_int 3);
       Capture_scope.Private (RegionId.of_int 3); Capture_scope.Static]);
  require "the full two-scope environment must replay" (Capture_scope.replay scope);
  require "an explicit static call argument can instantiate a declared callee parameter"
    ((List.hd (make ~actual_arguments:[RStatic] [free 7]).bindings).label = Capture_scope.Static);
  List.iter (fun action -> require "an absent/erased/escaping capture scope must refuse" (refuses action)) [
    (fun () -> ignore (make [RErased]));
    (fun () -> ignore (make [body 4]));
    (fun () -> ignore (make [free 8]));
    (fun () -> ignore (make [RVar (Bound (0, RegionId.of_int 7))]));
    (fun () -> ignore (make ~actual_arguments:[free 12] [free 7]));
    (fun () -> ignore (make ~actual_arguments:[body 4] [free 7]));
    (fun () -> ignore (make ~actual_arguments:[RErased] [free 7]));
    (fun () -> ignore (make ~actual_arguments:[] [free 7]));
    (fun () -> ignore (make ~source_parameters:[parameter 7; parameter 7] ~actual_arguments:[body 2; body 3] [free 7])) ];
  let first = List.hd scope.bindings in
  let private_binding = List.nth scope.bindings 1 in
  require "a callee-private region cannot be retagged as a caller region"
    (not (Capture_scope.replay { scope with bindings = first ::
      { private_binding with label = Capture_scope.Caller (body 3) } :: List.tl (List.tl scope.bindings) }));
  require "a private lifetime cannot be guessed static"
    (not (Capture_scope.replay { scope with bindings = first ::
      { private_binding with label = Capture_scope.Static } :: List.tl (List.tl scope.bindings) }))
