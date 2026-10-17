import Auths.Codec.PrincipalScheme
import Auths.Codec.ScopeTrustSelectors
import Auths.Codec.ScopeDecodedUse
import Auths.Codec.ScopeDecodeSafety
import Auths.Codec.ScopeDecodeExamples
import Auths.Codec.ScopeSelectors
import Auths.Codec.ScopeExamples

-- Actual sorting/validation constructor and constructor-earned native lookup.
-- Decoder success earns structural scope validity; complete byte-decoder
-- totality, canonical round trips and verifier/runtime composition remain open.
#check Auths.ScopeConstructor.constructor_refines
#check Auths.ScopeConstructor.constructor_validity
#check Auths.ScopeConstructor.constructed_lookup
#check Auths.ScopeConstructor.Examples.accepts_unsorted
#check Auths.ScopeConstructor.Examples.rejects_duplicate
#check Auths.ScopeConstructor.Examples.rejects_empty
#check Auths.ScopeConstructor.Examples.rejects_oversized

#check Auths.ScopeConstructor.constructed_principal_selection

#check Auths.ScopeConstructor.constructed_grant_selection

#check Auths.ScopeConstructor.DecodeExamples.accepts_own
#check Auths.ScopeConstructor.DecodeExamples.accepts_any
#check Auths.ScopeConstructor.DecodeExamples.refuses_unknown_tag
#check Auths.ScopeConstructor.DecodeExamples.refuses_truncation
#check Auths.ScopeConstructor.DecodeExamples.accepts_listed
#check Auths.ScopeConstructor.DecodeExamples.refuses_empty_list
#check Auths.ScopeConstructor.DecodeExamples.refuses_invalid_id
#check Auths.ScopeConstructor.DecodeExamples.refuses_collection_limit

#check Auths.ScopeConstructor.accepted_scope_valid

#check Auths.ScopeConstructor.decoded_scope_covers

#check Auths.ScopeConstructor.DecodeExamples.sorts_unsorted_list
#check Auths.ScopeConstructor.DecodeExamples.refuses_duplicate_list

-- Pending implementation-first batch: checked once the enlarged source unit
-- has been translated and its complete statement/source inventory reviewed.
#check Auths.PrincipalScheme.scheme_refines
#check Auths.ScopeConstructor.accepted_rule_valid
#check Auths.ScopeConstructor.accepted_trust_valid
#check Auths.ScopeConstructor.decoded_trust_principal
#check Auths.ScopeConstructor.decoded_trust_grant
