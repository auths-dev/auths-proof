# Content Epic 10 — Canonical Information Architecture and Route Ownership

**Status:** Complete in `auths-docs` commit `d3dc5db`.

**Depends on:** Content Epic 0 and
[`SITE_CONTENT_AND_LINK_AUDIT.md`](./SITE_CONTENT_AND_LINK_AUDIT.md).

## Outcome

Every public page has one primary section owner, one canonical route, one
stable identity, and a declared place in the complete documentation tree.

## Current problem

The site has 92 valid routes but no binding topic hierarchy. Legacy namespaces
(`/start`, `/guides`, `/quickstarts`, `/adopt`, and `/integrations`) make
ownership ambiguous. Sixty pages are navigational orphans.

## Implementation

- [x] Encode the complete tree in
  [`PROPOSED_SITE_HIERARCHY.md`](./PROPOSED_SITE_HIERARCHY.md) as a strict,
  parseable navigation contract.
- [x] Give every page `section`, `parent`, `navGroup`, `order`, and canonical
  `path` fields.
- [x] Reject missing parents, cycles, duplicate order, cross-section parents,
  and pages absent from the tree.
- [x] Move adoption and quickstarts under `/get-started`.
- [x] Move integrations under `/developers/integrations`.
- [x] Replace legacy `/start/*` and `/guides/*` routes with canonical section
  pages; prelaunch means no compatibility aliases are required.
- [x] Keep `/reference` and `/assurance` as explicit cross-cutting utilities.
- [x] Produce a migration manifest mapping every old page identity and path to
  its retained, replaced, merged, or deleted destination.
- [x] Delete generic pages that cannot name a distinct reader job.

## Acceptance

- All public pages occur exactly once in the canonical tree.
- No primary-section landing needs an unrelated namespace to represent its
  first layer of content.
- The route graph has no orphan, cycle, missing parent, or ambiguous owner.
- Old paths are absent from source, rendered links, search, sitemap, and
  Markdown surfaces.
