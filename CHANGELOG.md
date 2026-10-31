# CHANGELOG.md

## 2026-10-31 — K07

- User accepted D10 line-based ResponseContent patterns and visible validation errors retaining the previous valid configuration. Preserve Java flags/find semantics and the distinction between admission and display filtering.
- Added reusable compiled filter plans, bounded JVM-wide background filter work, stable rebuild snapshots/generations and new-row merging; Clear/removal/unload invalidate stale results. Keep already-admitted records during display overload and show a counter when unknown capture matches cannot be admitted. No regex hard-stop or full log-memory bound is claimed.
- Closed K07 in the recorded environment. Final source includes a targeted Reset fix: clear rejected-draft errors and supersede pending validation even when resetting to already-active defaults. CPython/Jython182 cases/181 pass/one accepted K05 limit; legacy characterization28; standalone and actual-Burp23 filter cases +23 native/UI checks pass. Real display/capture/clear profiles pass with30 once-forwarded HTTP requests,9 regex compilation attempts and3 numeric parses. Prior custom/isolated-regex checks keep their actual source hash and an unchanged-code scope proof. Final direct-entry normal/custom regression passes: one action/one CheckPage/exactly two new custom calls, raw payloads and correct cookie/token; delayed counters unchanged. Environment and closure recorded; prepared the user-requested K07 commit/push checkpoint, revision in Git history. K08 not started; generated runtime captures remain ignored.

## 2026-10-31 — K06

- Added EDT-published configuration versions for complete template workflows and callback logging decisions, native editor document observation with a 100 ms public-API polling fallback, a real status label, EDT startup and unload/partial-registration cleanup.
- Added bounded session ownership through the final Proxy response, request-reference tracking, private workflow cookie/token stores, ordered delta publication and joint Clear generations. Preserve the accepted global session model and explicit delivery/cross-target limits.
- Fixed unload during host registration with lifetime checks and rollback after each registration, without holding a mutex across host calls. Final native probe has 23 checks, including all three controlled cancellation points. Source version boundaries and the unchanged workflow code between wire/final versions are recorded in K06 evidence.
- Closed K06 in the recorded environment: CPython/Jython159 cases/158 pass/one accepted K05 hard-stop limit; standalone and actual-Burp15 session +23 native/UI checks; six directed wire cases (18 target requests/16 custom calls/two explicit drops); eight isolated lifecycle cycles; final direct-entry normal regression with exactly two custom calls and correct cookie/token/raw bytes. Added test-only gated fixture/EDT control, corrected HTML-entity assessment without replay, and preserved earlier attempts. Prepared the user-requested K06 commit/push checkpoint; revision in Git history, generated runtime captures remain ignored.

## 2026-10-31 — K05

- Implemented the selected bounded custom executor: one worker/one pending job, strict 1–30000 ms submission deadline covering compile/exec/call/conversion, explicit busy/timeout/closed outcomes and no replacement of still-running code. A JVM monitor and stable ThreadGroup coordinate worker creation across Jython interpreters/reloads; an extension-state listener closes admission and pending work on unload.
- Made Test asynchronous through the same executor and a Swing Timer, discarding outdated results. Freeze custom code/enabled/timeout for both template steps; cache compiled code without caching runtime namespaces or skipping top-level side effects. Preserve Unicode editor source and diagnostic text, including broken exception formatting.
- Closed K05a in the selected D08 scope. CPython/Jython 144 cases: 143 pass, one explicitly accepted hard-interruption limitation. Standalone and actual-Burp helper checks pass (13 executor cases/13 native-UI assertions); infinite Python and native waits verified only in externally bounded disposable JVMs. Eight real wire cases pass, including pre-/post-send timeouts, invalid input and finite capacity. Actual final unload/reload produces a new single worker and normal 2-call custom regression passes; prepared the user-requested separate K05 Git checkpoint; revision is in Git history. K06 implementation has not started.

## 2026-10-31 — K04

- After the K04 checkpoint, the user delegated the D08 execution-policy choice. Recorded K05a bounded in-process execution (one worker, one pending job, 500 ms default / 1–30000 ms shared deadline), preserving Jython semantics and explicitly excluding guaranteed hard cancellation. This is a planning decision only; K05 implementation has not started.
- User accepted the existing global session model and its cross-target limitation, plus explicit cookie deletion/empty-value and CSRF lifecycle rules. Workflow coordination remains K06.
- Corrected Set-Cookie recognition, expiry/Max-Age handling and template-cookie resurrection with tombstones; preserved unmanaged template cookies and byte-valued request bodies.
- Compile/validate CSRF patterns on document edits; distinguish invalid/no capture, no match, empty token and Clear. Preserve raw byte searches without implicit decompression.
- Closed K04 in the tested Burp environment: 131 cases on CPython/Jython (129 pass, 2 K05 defects), 26 successful traffic scenarios and final normal custom regression. Final root reload and 22 actual-helper/Java/Swing checks pass, including oversized regex repetition as a configuration error. Earlier traffic source and the final one-line exception guard have explicit hashes; original evidence is retained. Prepared the user-requested separate K04 Git checkpoint; revision is in Git history. K05 not started.

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
