# Content Epic 19 — Full-Site Content and Link Qualification

**Depends on:** Content Epics 10–18 and Platform Epic P11.

## Outcome

The failures recorded in the site audit become impossible to reintroduce.

## Implementation

- [ ] Crawl every canonical HTML page and every rendered internal link on the
  exact current docs head.
- [ ] Fail on orphan pages, missing parents, wrong active nav, broken
  breadcrumbs, missing previous/next, or duplicate canonical routes.
- [ ] Validate landing-card intent: primary cards must target descendants;
  cross-topic cards require an explicit Related topics label.
- [ ] Enforce page-type content contracts from Content Epic 11.
- [ ] Fail implementation guides with no qualified code and runbooks with no
  tested commands.
- [ ] Fail generic tested-scenario links that do not resolve to the exact
  scenario page and step.
- [ ] Verify every HTML, page Markdown, section Markdown, download, search,
  sitemap, discovery, and manifest target.
- [ ] Run unfamiliar-reader tasks for each top-level section.
- [ ] Publish a release report listing pages, links, orphans, code coverage,
  procedure coverage, accessibility, responsive checks, and known limits.

## Acceptance

- Zero orphan pages and zero broken or misleading landing cards.
- Every non-landing page has correct topic navigation.
- Every public link resolves to the promised reader job.
- The six unfamiliar-reader journeys complete without facilitator help.
- The audit report is generated from the deployed candidate and exact source
  heads, not a stale fixture.

