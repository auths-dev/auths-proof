import Auths.Composition.FacadeExamples
import Auths.Composition.ValidationExamples
import Auths.Composition.Examples
import Auths.Composition.PlanExamples
import Auths.Composition.Work
import Auths.Composition.Bounds
import Auths.Refinement.Production
open Aeneas Aeneas.Std Result

-- Loading the independent extractions together used to collide on anonymous
-- short instance names. The reviewed naming bridge preserves exact values.
namespace qualification.Composition.First
@[qualified_discriminant u16 [3, 9]]
inductive Reason where | left | right
example : read_discriminant Reason.left = 3#u16 := rfl
example : read_discriminant Reason.right = 9#u16 := rfl
end qualification.Composition.First

namespace qualification.Composition.Second
@[qualified_discriminant u16 [5, 12]]
inductive Reason where | left | right
example : read_discriminant Reason.left = 5#u16 := rfl
example : read_discriminant Reason.right = 12#u16 := rfl
end qualification.Composition.Second
