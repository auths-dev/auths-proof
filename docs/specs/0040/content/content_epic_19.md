# Content Epic 19 — Full-Site Content and Link Qualification

**Depends on:** Content Epics 10–18 and Platform Epic P11.

## Outcome

The failures recorded in the site audit become impossible to reintroduce.

## Implementation

- [x] Crawl every canonical HTML page and every rendered internal link on the
  exact current docs head.
- [x] Fail on orphan pages, missing parents, wrong active nav, broken
  breadcrumbs, missing previous/next, or duplicate canonical routes.
- [x] Validate landing-card intent: primary cards must target descendants;
  cross-topic cards require an explicit Related topics label.
- [x] Enforce page-type content contracts from Content Epic 11.
- [x] Fail implementation guides with no qualified code and runbooks with no
  tested commands.
- [x] Fail generic tested-scenario links that do not resolve to the exact
  scenario page and step.
- [x] Verify every HTML, page Markdown, section Markdown, download, search,
  sitemap, discovery, and manifest target.
- [x] Run deterministic unfamiliar-reader journey proxies for each top-level
  section. Moderated reader research remains a release activity and is named
  as a limit rather than being represented as automated evidence.
- [x] Publish a release report listing pages, links, orphans, code coverage,
  procedure coverage, accessibility, responsive checks, and known limits.

## Acceptance

- Zero orphan pages and zero broken or misleading landing cards.
- Every non-landing page has correct topic navigation.
- Every public link resolves to the promised reader job.
- The six unfamiliar-reader journeys complete without facilitator help.
- The audit report is generated from the deployed candidate and exact source
  heads, not a stale fixture.

## Qualification record

`npm run test:site` builds the report at
`outputs/site-qualification-report.json`. It evaluates the built deployment
candidate against the current release contract and records the exact docs head.
The report distinguishes structural accessibility and responsive stylesheet
qualification from browser-level assistive-technology checks and moderated
reader research.
