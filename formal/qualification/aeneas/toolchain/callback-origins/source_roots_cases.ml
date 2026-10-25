(* Authored for the final batch; no checks execute during implementation. *)
let refuses action = try action (); false with Invalid_argument _ -> true
let require message condition = if not condition then failwith message

let () =
  Source_roots.require Source_roots.names;
  Source_roots.require (List.rev Source_roots.names);
  let first = List.hd Source_roots.names and rest = List.tl Source_roots.names in
  require "an unrelated helper cannot replace one of the complete public entry points"
    (refuses (fun () -> Source_roots.require ("auths_gateway::unrelated" :: rest)));
  require "duplicating a root cannot preserve the public ABI by count alone"
    (refuses (fun () -> Source_roots.require (first :: first :: List.tl rest)));
  require "an adapter dependency is not another public root"
    (refuses (fun () -> Source_roots.require ("std::io::Write::write_all" :: Source_roots.names)));
  require "a public root cannot be omitted"
    (refuses (fun () -> Source_roots.require rest))
