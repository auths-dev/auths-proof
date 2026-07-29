import Auths
import Lean.Elab.Command
import Lean.PrettyPrinter
import Lean.Util.CollectAxioms

open Lean Lean.Elab Lean.Elab.Command

private def declarationKind : ConstantInfo → String
  | .thmInfo _ => "theorem"
  | .axiomInfo _ => "axiom"
  | .opaqueInfo _ => "opaque"
  | .defnInfo _ => "definition"
  | .quotInfo _ => "quotient"
  | .inductInfo _ => "inductive"
  | .ctorInfo _ => "constructor"
  | .recInfo _ => "recursor"

private def auditDeclaration
    (environment : Environment) (declarations : Array Json)
    (declarationName : Name) :
    CommandElabM (Array Json) :=
  match environment.find? declarationName with
  | none =>
      throwError
        "assurance inventory names missing declaration '{declarationName}'"
  | some info =>
      (liftTermElabM <| Meta.ppExpr info.type) >>= fun statementFormat =>
      collectAxioms declarationName >>= fun axioms =>
      pure <| declarations.push <| Json.mkObj [
        ("name", declarationName.toString),
        ("kind", declarationKind info),
        ("statement", statementFormat.pretty 120),
        ("axioms", Json.arr <| axioms.qsort Name.lt |>.map (toJson ·.toString))
      ]

run_cmd
  getEnv >>= fun environment =>
  Auths.theoremInventory.foldlM (init := #[])
    (auditDeclaration environment) >>= fun declarations =>
  IO.println <| (Json.mkObj [
    ("schema", "auths-proof-lean-assurance-audit/v1"),
    ("declarations", Json.arr declarations)
  ]).compress
