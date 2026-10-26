# ADR 0018: Fixed suffix on one verified gateway path field

**Status:** Proposed. The gateway compiler implementation is construction
evidence; no production qualification is claimed.

**Date:** 25 October 2026

## Context

AP-SPEC-071's first Google write uses Docs `documents.batchUpdate`, whose
documented endpoint is `/{documentId}:batchUpdate`. The existing recipe path
grammar can produce `/{documentId}/batchUpdate`, which is a different URL.
[Case 0010](../research/domains/abstraction-cases/0010-typed-path-field-suffix.md)
also finds Twilio's independent `/{Sid}.json` shape. Splitting a fixed suffix
into a separate segment or asking an agent to add it to a document ID is not
an exact resource binding.

## Proposed decision

Add a closed `field-suffix` path segment: one typed, native-verified field
followed by a fixed, compiler-validated `:` or `.` suffix. The compiler
restricts the suffix to 2–32 safe ASCII bytes, consumes the field, and shows
both in operator review. The unchanged kernel constructor encodes the field
once as a segment; the gateway then appends the validated suffix to that final
segment. No query, fragment, slash, provider
name, callback or runtime-selected suffix is allowed. Its exact source is
committed by the existing recipe digest; existing `/2` recipes and digests
remain byte-identical. The operator still approves the new digest and its
production qualification separately.

This is request construction only. It does not establish that Google accepted
the request, that `requiredRevisionId` was honored, that one replacement
occurred, or that any Twilio behavior is authorized. Those assertions remain
in domain references and installed evidence. The current Google reference
compiles the correct path and body, but no live Jules write or independent
producer probe has passed.

## Alternatives and risks

One recipe per pinned document ID would avoid a grammar change but would make
the integration unit resource-specific and hinder ordinary task picking.
Putting `:batchUpdate` into the agent's document ID would make the signed
resource ambiguous to the human and couple provider routing text to a
resource handle. A general string-template path would allow much broader URL
construction than this need warrants.

The remaining risk is a provider interpreting encoded field bytes differently
from the gateway's segment model. Installed conformance must count actual
requests and compare the final request target. No response or effect claim
follows merely from this ADR. Production promotion requires the second
installed domain and hostile evidence in Case 0010, plus the gateway's normal
operator approval and qualification gates.
