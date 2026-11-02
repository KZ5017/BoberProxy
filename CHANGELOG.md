# CHANGELOG.md

## 2026-11-02 — Approved compact sidebar checkpoint

- Record user approval and requested commit/push of the wider fixed sidebar, compact aligned control rows and shorter Output area. Existing processing behavior is preserved; syntax/encoding/whitespace checks passed. Historical Burp reports remain scoped to their original source versions; K11 has not started.

## 2026-11-02 — Equal payload parameter groups

- Give Payload 1/2 label-and-field groups equal halves of their row, matching the custom/timeout split. Preserve editing and processing behavior.

## 2026-11-02 — Align compact sidebar controls

- Split cookie/CSRF control rows into equal thirds, custom/timeout into equal halves, and reduce Output preferred height by one font-metric line. Keep accepted fixed width and processing behavior; awaiting user preview.

## 2026-11-02 — Compact sidebar row preview

- Place size/comparator/value, four equal logging buttons, each session checkbox with its Clear/Show pair, and both payload fields into compact rows. Capitalize Size Filter and logging button captions. Keep the accepted widened fixed width independent of row preferred sizes; actions/defaults unchanged. Awaiting user preview.

## 2026-11-02 — Sidebar width preview

- Increase the computed fixed sidebar width by30% and shorten session checkbox captions to Auto-update Cookies / Auto-update CSRF. Preserve actions/defaults and fixed-width resizing behavior; awaiting user preview before further layout changes.

## 2026-11-02 — UI03 Git checkpoint

- Prepare user-requested commit/push of the closed Python-editor implementation, bundled dependency/license, installation documentation and validation evidence. Runtime captures remain ignored; source/JAR hashes match actual Burp results. K11 not started.

## 2026-11-02 — UI03 validation closed

- Archive matching-source actual Burp PASS20 editor/18layout/10cleanup/UI/24logging, including four-space Tab, Enter indentation and private Test OK; user approves editor and reports no Errors. Historical failed reports remain intact.
- All required UI03 checks complete. K11 not started; no additional source change, traffic or Git action for closure.

## 2026-11-02 — Isolate editor keys across Burp classloaders

- Reproduce stale shared RSTA actions/default typing across independent classloaders and fix with per-editor key/action maps using its own EditorKit. Do not reset shared Burp/Swing defaults.
- Isolated loader proof and native22 editor +18/10/24 checks pass; preserve two initial actual-helper failures. Final main/helper reload and manual Test confirmation pending.

## 2026-11-02 — UI03 bundled Python editor candidate

- Bundle pinned RSyntaxTextArea3.6.3/license/provenance and replace the custom editor with Python highlighting, line numbers, four-space Tab/indentation, bracket matching and undo/redo at the previous outer dimensions. Keep existing execution/Test/Reset/session flow.
- Load dependency/theme resources off EDT from extension-relative lib path; use local theme/key settings, visible plain-editor fallback, and ignore unchanged custom snapshots. Document complete-folder installation.
- Native21 editor +18layout +10cleanup/UI +24logging and CPython custom13 pass; final actual Burp/helper/manual gate pending. Preserve failed harness attempts; no network traffic or Git checkpoint.

## 2026-11-02 — Targeted custom code-editor plan

- Add UI03 plan for a bundled RSyntaxTextArea JAR and a narrow custom-editor replacement, preserving current dimensions and execution behavior. Include dependency packaging, focused validation and installation handoff.
- Planning only; production source, Burp state and dependencies unchanged. K11 not started.

## 2026-11-01 — SI00/UI02 Git checkpoint

- Prepare user-requested checkpoint of closed SI00 research/declined integration and UI02 shortcut/status-strip work, including synthetic evidence and private helpers. Generated runtime data stays ignored.
- Preserve actual-tested hashes separately from the four cosmetic button flags; current source passes syntax/line-ending checks and differs from the approved UI02 candidate only by those flags. K11 not started.

## 2026-11-01 — Simplify Proxy settings button appearance

- Disable hover background, painted border/focus ring and rollover on the local shortcut button. Preserve its icon, native click behavior and keyboard focus. Cosmetic change only; reload/visual confirmation pending.

## 2026-11-01 — UI02 validation closed

- Archive actual Burp UI02 layout/helper PASS18/10/24 with matching source hash and user approval of native Proxy settings opening, fixed status strip and empty Errors. All required UI02 checks complete; no additional source change or traffic. K11 not started.

## 2026-11-01 — UI02 settings shortcut and visible status strip

- Add tab-row Proxy settings shortcut using original native button/icon; add CheckPage Template spacing. Keep host control in place and invoke its original event source; handle unavailable controls visibly.
- Move filter/operation labels below the log into a fixed single-row strip, with full-text tooltips; clarify Logging enabled/paused captions. Preserve processing, source Latin-1/CRLF and existing sidebar layout.
- Native18 layout +10cleanup/UI +24logging and CPython filter23 checks pass. Preserve initial/helper failures and corrected evidence; final actual Burp/manual gate pending. No traffic, K11 or Git checkpoint.

## 2026-11-01 — Close SI00 research without integration

- Record explicit user decision to retain existing cookie/CSRF workflow and abandon SI01–SI05. Preserve research evidence and restored Burp configuration; main source unchanged.
- Clarify primary purpose in README/handoff: CLI payload transformation, rotating session/token tracking and CheckPage result retrieval. K11 remains separate/not started; no new traffic or Git checkpoint.

## 2026-11-01 — SI00 Burp restoration confirmed

- Recorded user-confirmed own-rule shutdown, original Extensions jar collection setting, observer removal and fresh all-OFF root with empty Errors. G00 is undecided; user requested a clearer explanation before selecting integration scope. No source, traffic or Git action.

## 2026-11-01 — SI00 directed measurements collected, G00 pending

- Final unmodified-main redirect/template trial passes13 checks:POST/GET/POST, native response-cookie propagation,2custom calls, raw bodies and exact/delayed counts, owned cleanup.
- Added capability assessment and limited native cooperation proposal; preserve Compatibility default and documented expiry/shared-jar/macro-order/deadline limits. G00 acceptance and manual restoration remain pending, production source unchanged, no SI01/K11/Git action.

## 2026-11-01 — SI00 macro failure, deadline and existing Cookie measurements

- Actual missing/slow macro responses do not prevent OLD-token parent sends; a100ms client timeout did not cancel the delayed native send. Counts/owned cleanup/delayed observations recorded; no application actions or retries.
- Characterized existing owned Cookie headers; preserve first FAIL caused by empty macroItems array versus null and attach corrected assessment from identical captures.
- Prepared separate CRLF main redirect/template fixtures and a finite controller, pending manual profile gate. Main source unchanged; no G00/SI01/Git yet.

## 2026-11-01 — SI00 native macro correlation

- Recorded actual API/Proxy and two concurrent Proxy macro-token correlation:11 checks,5 parent GETs/4 macro GETs/0application actions, exact raw query and own cleanup. Production source unchanged.
- Prepared finite missing-token/slow macro characterization controller; only syntax checked so far. Requested isolated 404 macro profile before negative traffic. G00 remains open.

## 2026-11-01 — SI00 session API inspection started

- Unmodified main's normal native-cookie RT/CheckPage workflow passes; controlled shared-jar interleave preserves local token but substitutes FOREIGN cookie, demonstrating missing native flow isolation. Counts/raw/custom remain correct; delayed checks unchanged. nanoTime trace confirms existing custom calls precede native rules. Macro recorder material/controller prepared; scoped macro profile gate pending, no main/backend implementation.

- Enabled Extensions collection by user; collection and Secure HTTP/HTTPS measured successfully. Max-Age=1-only cookie remained sent after >2s with null API expiry, a real difference from own cookie manager. Corrected interpretation of the immutable combined Expires/Max-Age0 report: suppression, not proven physical deletion or isolated Max-Age0 behavior.
- Prepared unchanged-root native-cookie workflow and finite interleave custom fixture (six private native checks); main UI setup gate pending. No backend implementation or G00 decision yet.

- Native cookie-only rule PASS on API/Proxy; actual callback order recorded. Six HTTP cases show correct tested domain/path selection, valid empty/deleted values, Proxy response collection and absent Extensions response collection in the current configuration. Prepared separate HTTP/TLS edge fixtures (seven self-checks) and expiry/Secure controller; collection/profile confirmation pending. Main source unchanged, no SI00/G00 closure yet.

- Actual no-rule baseline PASS: one API GET and one Proxy GET, raw query preserved, no injected cookie/session action, complete own cleanup. The jar alone did not inject the seeded cookie. Native cookie-only rule profile documented; user setup confirmation pending, no rules comparison or macros run yet.

- Actual cookie API PASS16 and owned cleanup confirmed in Burp, main unchanged/OFF. Same-name distinct paths coexist; expired-cookie enumeration recorded without inferring outgoing behavior. Prepared scoped wire observer/controller and separate loopback fixture: native20 and fixture5 self-checks pass; actual wire-helper load gate pending, no session rule/macro yet.

- User authorized plan execution. Added finite, owned synthetic cookie API probe and actual Burp entry point; private native23 checks cover cleanup variants, unrelated data preservation and partial registration/unload. No production source change, network request or native session-rule/macro configuration yet.
- First actual Burp API gate pending. SI00/G00 not closed; SI01/K11 and new Git checkpoint not started.

## 2026-11-01 — Burp session integration plan

- Added a detailed SI00–SI05 implementation plan: isolated capability/order probes, compatibility-preserving integration layer, native cookies, UI/Clear/lifecycle, conditional macro token preparation and final regression. Includes shared-state ownership, cookie API limitations, token/custom timing, decision gates, test matrix, evidence and rollback.
- K11 deferred by user. Planning only: no production/test implementation, Burp settings, traffic or commit/push changed. UI01 checkpoint remains `9bf37c8`.

## 2026-11-01 — UI01.6 final validation closed

- User requested a commit/push checkpoint of the complete closed UI01 state, including its plan, helpers and synthetic evidence. Generated runtime captures stay ignored; closure reports retain their validation-time Git state.

- Actual root/helper PASS with matching source, user confirmed no Errors and exact setup. Final passive unmatched GET/binary256/empty204 and normal RT→CheckPage/custom pass: one action, two target requests, two custom calls; cookie/token/raw payload correct, delayed counters unchanged. User confirmed final rows/viewer/204 Body size0 and no Errors after traffic; all UI01 gates closed. Evidence archived separately under final-ui016; no source change, commit/push or K11.

- User accepted the final layout and authorized the postponed regression. Updated native layout expectations for full-width pairs, local regex viewports, Output behavior, split initialization and renamed capture controls. Updated the old numeric-error caption assertion; production source unchanged.
- CPython/Jython211/210/one accepted K05 limit, native3 profiles x23 geometry/behavior checks and existing cleanup/logging pass. Preserve failed test-expectation attempts with their original source hash. Actual Burp/helper and directed normal traffic gates also passed; no commit/push or K11.

## 2026-11-01 — UI01.6 Output appearance and neutral clicks

- Hide Output's insertion cursor and remove input-style borders while retaining read-only text selection and keyboard copy.
- Move focus out of active sidebar fields when left-clicking owned neutral backgrounds or labels. Use local listeners, stopping at interactive widgets; no global hook or timer.
- Startup UI01.6; no tests/rendering/traffic, awaiting user live preview.

## 2026-11-01 — UI01.5 consistent size terminology

- Use Total size / Body size for log columns and capture choices, Size filter for the field label, and Minimum / Maximum / Not equal for comparators. Align numeric-validation caption and Body size display-filter label. Map UI captions to existing internal filter values so comparison behavior is preserved.
- Startup UI01.5; no tests/rendering/traffic, awaiting manual preview.

## 2026-11-01 — UI01.4 workflow checkbox row

- Put Use CheckPageTemplate and AutoFollow redirect on RT in one equal-width row through the existing layout helper. Startup UI01.4; no tests/rendering/traffic, awaiting manual preview.

## 2026-11-01 — UI01.3 Response regex scrollbar space

- Reserve the horizontal scrollbar's native height in the initially empty Response regex viewport, keeping characters visible when overflow reveals the scrollbar. Visibility remains AS_NEEDED; other controls unchanged. Startup UI01.3. No tests/rendering/traffic; awaiting user live preview.

## 2026-11-01 — UI01.2 button rows and initial viewer balance (awaiting manual preview)

- Initialize request/response editors at equal widths once laid out; share resize space equally while preserving manual divider movement.
- Make Injecting/Site map buttons fill their rows; use one shared equal-width layout for logging, cookie, CSRF and Test/Reset button pairs. Keep CSRF Reset to default in place.
- Give Response regex the same single-visible-row horizontal-scroll presentation as CSRF. Existing actions and regex evaluation remain. Startup UI01.2; no tests, rendering or traffic, as requested. Final regression remains deferred; no commit/push.

## 2026-11-01 — UI01.1 compact layout (awaiting manual preview)

- Target approximately two-thirds of the previous measured sidebar reference; split logging actions, workflow toggles and session controls across shorter rows. Reduce editor viewport columns and show a single CSRF regex row with a local horizontal scrollbar.
- Existing actions/defaults remain; startup UI01.1 identifies this candidate. No tests or rendering/traffic run, as explicitly requested by the user. Earlier UI01 PASS evidence remains tied to its original source. Final regression deferred until layout acceptance; no commit/push.

## 2026-11-01 — UI01 first layout delivered; final test deferred

- Replaced the outer split with a measured fixed-width control sidebar and preserved inner viewer/table splits. Added independent control groups/local forms, compact equal Test/Reset, visible timeout units and viewport-aware vertical scrolling with editor-local horizontal scrolling.
- Preserved widget constructors/defaults/actions and122 exact core definitions. Final source logic211/210/one accepted K05 limit, three font profiles with12 layout checks, existing native logging/runtime/custom regressions pass. First local AWT/Swing import error and visual alignment correction retained in evidence. Actual Burp/user visual gate and final normal workflow pending; no commit/push or K11 work.
- Actual root/helper PASS1/10/24 with matching source hash and user-reported functional correctness. Actual13pt sidebar706px, Test/Reset75px; passive GET/raw-query/binary256/empty204 checks pass. Final table/viewer confirmation and configured normal workflow remain pending.
- User subsequently confirmed passive rows/viewer/204 BodyLen0 and explicitly deferred the normal workflow/custom test until further small layout changes, to be described separately. No normal test request sent; no further code changes at this handoff. Full UI01 regression closure remains incomplete; retain existing evidence. No commit/push or K11 work.

## 2026-11-01 — UI01 plan

- Added a single-round implementation plan for the right control sidebar: measured fixed width, independent layout groups, compact equal Test/Reset buttons and viewport-aware scrolling. Documented code causes, preserved behavior, concrete steps, U01-U10 acceptance, current Burp state and scoped rollback.
- Planning only; no production/test code changed, no traffic or Burp reload, and no commit/push. K11 remains separate.

## 2026-11-01 — K10/B (closed; no commit/push)

- After closure, the user authorized a combined K10/A+B commit/push checkpoint, superseding the earlier implementation-time restriction. Included source, helpers, updated documentation and synthetic evidence; runtime captures remain ignored. Revision in Git history; closure JSON preserves its pre-checkpoint state.
- Continued from closed, uncommitted A under an explicit no-commit/push instruction. Removed only the uncalled permissive converter; kept strict wire conversion, native filter/container semantics and existing Content-Length normalization.
- Empty native bytes replace null-first template Clear; visible fixed-code UI errors, safe startup withdrawal/reporting, cleanup of failed filter drafts and robust parser diagnostics. Updated result docstrings and Site map scope tooltip. Core sessions/custom/filter/archive/redirect/proxy behavior preserved by source comparison.
- README/AGENTS now describe actual installation/UI, serialized global-compatible workflow state, raw payloads, scope, GET redirects, filtering/archive/budgets and measured/version/hard-stop limits. All46 findings have individual status entries. Local211/210/1, native runtime15/23 and actual Burp6/10/24/23 pass. User confirmed passive UI and English scope tooltip; final normal action/CheckPage succeeds with exact payloads/cookies/token and exactly two custom calls, delayed counts unchanged. K10 closed, K11 not started; explicit no commit/push honored.

## 2026-11-01 — K10/A

- Two user-authorized K10 sessions share one current-code inventory; conversion compatibility, user documentation and aggregate closure remain B.
- Removed unused fifth editor/constructor references/imports/helpers/fields, undefined sync call and redundant selection-mode/proxy-toggle setup. Native callbacks and tested internal APIs retained.
- Code/type-only callback diagnostics contain output failures. CheckPage fallback and partial logging admission preserved; HTTP analysis errors visible. CPython/Jython205 cases/204 pass/one accepted K05 limit; private native cleanup/storage/UI and prior helper checks pass. Old editor doubles updated for non-null setMessage; failed fixture attempt retained.
- Closed K10/A: actual Burp6 diagnostic cases/10 cleanup-UI checks/24 logging checks PASS, user confirmed no Errors and passive viewer/BodyLen0. Three passive requests and final normal action/CheckPage pass with exact bytes, cookies/token and exactly two custom calls; delayed counts unchanged. Recorded source scope, environment and B handoff. K10/B, K11 and commit/push not started.

## 2026-11-01 — K08–K09

- Prepared the user-requested combined K08–K09 commit/push checkpoint, including source, test helpers, documentation and synthetic evidence. Revision in Git history; generated runtime captures remain ignored.
- User authorized a combined round with internal storage/model/lifecycle gates. Characterized the actual persisted-message API; exact bytes passed, but content remained readable after deleteTempFiles, so explicit reclamation was not established. Selected an owned temporary archive with metadata-only log records and background readers/cleanup.
- Added append-backed newest-first row views, batched insert notifications, one sorter/selection listener, shared32MiB raw admission budget, bounded worker queues and visible admission pause on overload/write failure. Preserve already-accepted rows and HTTP forwarding; Clear generations prevent stale restoration. Viewer/template/Site map read in background with selection guards and unchanged scope behavior.
- Fixed batch replacement event boundaries, explicit unload reference release and concurrent rejection-counter updates. Actual Burp rejected null viewer content; switched to empty native byte arrays and stopped timers before potentially failing viewer cleanup. Closed the combined round: final CPython/Jython199 cases/198 pass/one accepted K05 limit, standalone and actual-Burp15 storage +24 native/UI checks, eight native UI/archive cycles, seven directed wire cases385 once-forwarded requests, and final direct normal regression with exactly two custom calls. Isolated768MiB content/384MiB heap and100k model-metadata measurements pass with original hashes/scope limits. Preserved infrastructure failures, moved parallel wire tests to dedicated18772 fixture/backlog128, verified exact viewer/Site map bytes and delayed counters. K10/K11 not started; no commit/push.

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
