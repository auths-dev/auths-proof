-- Reuse only the existing reviewed UTF-8/String projections; no Auths body is modeled.
import qualification.aeneas.generated.profile_construction.Types
import qualification.aeneas.generated.codec.FunsExternal
namespace auths_profile_construction
abbrev core.str.Str.as_bytes := _root_.core.str.Str.as_bytes
abbrev alloc.string.String.as_bytes := _root_.alloc.string.String.as_bytes
abbrev alloc.string.String.Insts.CoreOpsDerefDerefStr.deref :=
  _root_.alloc.string.String.Insts.CoreOpsDerefDerefStr.deref
end auths_profile_construction
