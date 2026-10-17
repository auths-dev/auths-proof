import Aeneas.Data.Discriminant
/-!
The pinned Aeneas attribute gives anonymous instances short global names.
Independent extractions of the same Rust enum consequently collide on import.
This attribute reuses the pinned generator without changing its match body or
values. Only the instance command's namespace changes to the full declaration
name. Lean still elaborates and kernel-checks every generated definition.
The qualification gate records this exact metadata-only normalization.
-/
open Lean Elab Term Meta
open Lean.Parser.Term Command
namespace Auths.Support.Discriminant
syntax (name := qualifiedDiscriminant) "qualified_discriminant" ident ("["num,*"]")? : attr
initialize qualifiedDiscriminantAttribute : AttributeImpl ← do
  let attrImpl : AttributeImpl := {
    name := `qualifiedDiscriminant,
    descr := "Pinned Aeneas discriminants with declaration-scoped instance names",
    add := fun declName stx _ => do
      let (ty, values) ← match stx with
        | `(attr| qualified_discriminant $ty) =>
          pure (← Aeneas.Discriminant.elabTypeToken ty, none)
        | `(attr| qualified_discriminant $ty [$x,*]) =>
          pure (← Aeneas.Discriminant.elabTypeToken ty,
            some ((x.getElems.toList.map Syntax.isNatLit?).map Option.get!))
        | _ => throwUnsupportedSyntax
      liftCommandElabM do
        let commands ← liftTermElabM
          (Aeneas.Discriminant.generateReadDiscriminantCmds declName ty values)
        match commands with
        | [definition, instanceCommand] =>
          elabCommand definition
          withScope ({ · with currNamespace := declName }) (elabCommand instanceCommand)
        | _ => throwError "Pinned Aeneas discriminant generator changed"
  }
  registerBuiltinAttribute attrImpl
  pure attrImpl
end Auths.Support.Discriminant
