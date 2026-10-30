# CHANGELOG.md

## 2026-10-30

- Started K03 at the user's request after the clean `1042978` checkpoint: captured AutoFollow selection, preserved passive Proxy actions, added service-based redirect resolution, once-only response updates, explicit loop/limit/invalid-target outcomes and a shared monotonic scheduling budget. K03 is now closed in the recorded environment.
- Added K03 logic/native/loopback and action probes. CPython/Jython: 93 passing cases, 6 known later defects. Real blocking API deadline checks pass after correcting fixture tracking and Windows listener exclusivity. The same-real-callback instrumented action matrix, three manual request/response Forward pairs, all eight redirects including local TLSv1.3, and a final direct-entry normal/custom regression pass. Separate-extension action probes retain their topology limitation; no broad third-party listener or HTTP/2 compatibility claim is made.

- Saved and pushed the full K00/K01 checkpoint as `04d6398` on `origin/main` before starting K02.
- Implemented K02 lossless template conversion, single-pass marker substitution, custom element type validation, original diagnostics through workflow reporting, and zero response body lengths, with blank cells for unknown lengths and native Swing sorting coverage. Raw query/form priorities and send/fallback behavior remain unchanged.
- Completed K02 in Burp Community 2026.10.1 / Jython 2.7.4 / Java 26.0.2: 65 of 74 cases pass on both runtimes, with 9 later-round defects explicitly retained; 23 actual-helper/native Swing checks and all eight final template traffic scenarios plus five active unmatched byte controls pass. Final reload, pre-/post-send failures, original custom diagnostics, exact request bytes and operation counts are recorded in the K02 evidence. Earlier candidates and the final source-only patch are retained. K03 has not started.

- Prepared the user-requested separate K02 Git checkpoint, including source, documentation, reusable tests and synthetic evidence; generated runtime files remain ignored. Further implementation is deferred to a separate round.

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
