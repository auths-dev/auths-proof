-- Root module for the pinned Aeneas qualification corpus.
--
-- Algebra and authority generated modules intentionally live in separate
-- import closures because both represent the same Rust algebra carrier under
-- Aeneas' crate-local namespace rules. The qualification runner builds and
-- audits each closure independently.
import qualification.aeneas.generated.model.Funs
