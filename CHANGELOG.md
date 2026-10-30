# CHANGELOG.md

## 2026-10-29

- Added `docs/stabilizacios-terv/` with a Hungarian, twelve-round stabilization plan, complete finding coverage, behavior decisions, validation criteria, and execution handoff templates.
- Planning only: `BoberProxy.py` was not modified, and no implementation rounds were started.
- Subsequently started K00 at the user's request: added isolated CPython/Jython reproductions, a loopback HTTP fixture, Burp traffic probes, baseline measurements, and execution evidence. The production extension remains unchanged.
- Completed the K00 functional baseline, including real cookie/CSRF and two-call custom CheckPage traffic; retained configuration-mismatch attempts and recovered the placeholder-path trace.
- Prepared K01 code changes: select the HTTP API before sending, normalize response types, remove polling/retry fallback, preflight templates, and distinguish pre-send from post-send workflow failures. Post-send failures drop the original proxy request instead of forwarding an already sent operation again.
- Completed K01 regressions and standalone Java/Swing checks: 39 checks pass on CPython and Jython, with 12 separately tracked known defects remaining. In-application reload, passive traffic, empty-CheckPage preflight, normal CheckPage traffic, controlled post-build failure, connection-close-after-acceptance, and the final two-call custom regression were verified in Burp Community 2026.10.1 / Jython 2.7.4 / Java 26.0.2.
- Archived the K01 source-only patch and documented that Burp's extension-drop error page can carry HTTP 200; failure validation checks the body and target-side operation count.
- Prepared the user-requested K00/K01 Git checkpoint, including plans, helpers and synthetic evidence; generated runtime captures remain ignored. HTTP fixtures retain exact CRLF bytes through Git attributes.

## 2026-05-08

- Added `AGENTS.md` with repository scope, guardrails, risks, and handoff workflow.
- Added `AI_NOTES.md` with assumptions, unverified items, validation guidance, and next steps.
- Added this `CHANGELOG.md` for lightweight repository-level documentation tracking.
- Added a small documentation links section to `README.md`.
