# Stripe demo design language

The Stripe demos use the visual language established by the REST API
authorization demo. They should feel like members of one product family even
when an operation needs a different interaction model.

## UX

- Use a warm white grid canvas (`#f6f5f1`) and white evidence surfaces.
- Use near-black (`#111310`) for primary copy and the execution boundary.
- Reserve Auths blue (`#3157d5`) for the brand marker, selected emphasis, links,
  and the primary action.
- Use green (`#167456`) only for verified or allowed outcomes and red
  (`#a83934`) only for denied or failed outcomes.
- Lead with the exact bounded operation and its safety claim. Keep supporting
  prose visibly secondary.
- Put policy and liability facts before the action. Put the credential-bearing
  action inside a dark workbench so the authority boundary is visually explicit.
- Show the canonical receipt on a white evidence surface with JSON on a
  near-black code surface.
- Preserve readable keyboard focus, semantic headings, status text that does
  not rely on color, and a single-column mobile layout.

## Architecture

The family shares tokens, typography, spacing, navigation, workbench, outcome,
and receipt conventions. Each demo may compose those primitives differently
for its operation, but it must not introduce an unrelated palette or visual
metaphor.

The web assets remain self-contained in each demo so a profile can compile,
test, and deploy without importing another profile. This intentionally avoids
turning visual consistency into runtime or package coupling. When the language
changes, update the family together and run every demo's web smoke test.

## APIs

The design system does not change HTTP routes, request bodies, receipt schemas,
or authorization behavior. UI controls continue to call only their owning
profile's endpoints. Presentation must make the existing contract legible; it
must never imply broader authority, successful downstream effects, or a refund
when the API evidence does not prove one.
