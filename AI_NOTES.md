# AI_NOTES.md

## Current K07 closed in recorded environment (2026-10-31)

- User authorized K07 after pushed K06 `9819d46`; worktree clean on entry. K07 closed in the recorded environment; user requested a separate commit/push checkpoint, revision in Git history. K08 not started.
- D10 explicitly accepted via async reply: ResponseContent one regex per line, commas inside patterns preserved; other fields remain comma lists. Invalid regex/numeric input shows an error and keeps the last valid filter. Preserve Java engine, per-field flags, admission/display distinction and full response searches; bounded background work, no guaranteed regex hard cancellation.
- Implemented compiled CaptureFilterPlan/DisplayFilterPlan, one FilterWorker per JVM group BoberProxy.filters.v1 (128 row jobs +3 latest controls,128 completed,1 active), EDT result timer20ms/32 results/soft6ms between operations, stable rebuild snapshots and filter/log/removal generations. Last valid filter survives invalid input; unchanged regex/numeric plans reused. Cheap metadata rejection precedes regex queue; busy capture unknowns are explicitly counted/rejected, already-admitted rows retained even if display work is busy. Empty display/capture resets remain usable without replacing stuck workers. Root Clear captures epoch before callback analysis, Clear selected preserves unrelated pending admission. UI closes filter timer/dialog/queues on unload.
- FINAL candidate SHA-256 1309ff082c80aeab7bf1775a62f3679f3409aee73a5aadc777feed2137db300b. CPython/Jython182 total/181 pass/1 accepted K05 limit. Legacy Java characterization28 pass. FINAL native source23 cases +23 UI checks pass standalone. Prior67d68... actual Burp21+22 and passive traffic pass; archived before-reset-fix. K05 custom-native13+13 and expensive Java regex isolated25s checks pass on prior67...; final-reset-change-scope.json proves all source outside _apply_display_filters unchanged. The last fix advances intent even for Reset equal to active defaults and clears its draft error; two failing old-source cases retained in reset-before-fix.json. Never run the isolated regex child inside Burp.
- User confirmed final instrumented K07, all three startup lines, actual native23+23 PASS and no Errors. Directed display/capture/clear traffic all passed:30 client/target requests,0 workflow actions,9 regex compilation attempts,3 numeric parses, no per-row compilation, no restored pre-Clear data and no late extra target requests. See wire-summary.json. Source remains final1309.... Do not replay these scenarios or rerun wrapper smoke against a loaded wrapper: shared ignored channel filenames.
- User confirmed direct root reload and normal setup with no Errors. Final direct-normal-final regression passes:1 action/1 CheckPage/exactly2 NEW custom calls, raw payloads preserved, first token None and second csrf.k00-workflow.1, correct cookie/token. Delayed target/trace recheck remains1 action/2 requests/2 custom records. No further K07 traffic or manual gate remains; closure.json has14 successful checks, environment.json records versions and final UI.
- CURRENT UI: only direct root K07; unprefixed request-template.http/checkpage-template.http and runtime/custom-k07-pass-through.py (trace k07-custom-trace.jsonl), q/w,2000ms/defaultCSRF; template/CheckPage/custom/two automatics ON, AutoFollow/Intercept OFF, default log/display filters, unpaused. Cached normal fixture sid/token k00-workflow.1. Confirm/reset before K08; do not assume all OFF. Instrumented wrapper removed: do not send its file commands.
- Standalone K07 wrapper smoke9 checks pass on final1309..., no network. Actual test entry scoped only X-Bober-Test-Run:k07-* at127.0.0.1:18765; test-only namespace compile/number counters, finite5s rebuild gate, instance-scoped local file commands, none of this is in production source. [K07 evidence](docs/stabilizacios-terv/eredmenyek/K07/README.md) records F26/F27/F28 and E35-E40, exact source boundaries and remaining hard-stop/store limits. Generated runtime files stay ignored; closure.json records validation-time Git state before the requested checkpoint.

## Prior K06 closed in recorded environment (2026-10-31)

- Base: pushed K05 `b3464a6d682dd355ac7ff6aead1964e2ce66f03d`. K06 closed; user requested a separate commit/push checkpoint, revision in Git history. FINAL source SHA-256 `ddf7d0a34ebe4017b4d5bb76e35b081491650f51752cc5fda524b8a4a1e6ba91`; prior wire candidate `07f5bd3a...` preserved with its actual hashes.
- EDT-published config, real status label, session ownership through final Proxy response, private workflow state, ordered global delta publication and Clear epochs implemented and checked. Accepted D06 global/cross-target and D08 hard-stop limits remain; publication fallback100ms is not a guaranteed bound, unknown final delivery retains ownership until response/Clear/unload. See closure.json.
- CPython/Jython final159/158/1 accepted K05 hard-stop limitation. Final standalone AND actual-Burp helper15+23 pass; real editor checks, all three registration cancellation cases clean, user confirmed no Errors. Root passive traffic passed on prior candidate. All earlier measurements retain their actual hashes.
- User confirmed instrumented loading with both expected startup lines and no Errors. Six directed wire scenarios pass on 07f5...: normal, pairing/passive interleave, Clear during RT, Clear during final CP, mid-RT settings change, unload during RT. Aggregate: 11 clients, 9 actions/7 CheckPages/18 target requests, 16 custom calls, two explicit DROP actions; delayed target recheck has no extra requests. See wire-summary.json and filtered same-message/target/custom traces.
- Clear-RT initially assessed false solely because Burp encoded spaces as numeric HTML references. Captured body + ACTION_DROP=3 + target count already prove correct behavior. Assessment decoder fixed and unit-tested; prior false assessment retained, original capture re-evaluated WITHOUT request replay.
- First direct-entry attempt had HTTP success but absent requested K06 trace. Saved direct-normal-before-final-startup-guard with the actual failed custom assessment; its cause was not established. FINAL attempt succeeds: one action/two target requests/exactly two new custom calls, raw payloads, first token None and second csrf.k00-workflow.1; delayed target/trace recheck unchanged. See direct-normal-final and closure.json.
- Final review reproduced unload DURING tab/HTTP/Proxy registration: late listeners/orphan UI were possible (startup-race-before-fix.json). Fixed only registerExtenderCallbacks lifetime checks/withdrawal, no host calls under a lifecycle mutex. final-change-scope.json reconstructs old source and proves all code outside registration identical (apart from final blank line). Previous successful logic/native/lifecycle/patch/helper artifacts archived under before-final-registration-guard; wire evidence keeps old source hash, never relabel it.
- FINAL source logic/native/lifecycle and actual direct normal/custom regression all pass. No pending UI request or K06 gate. No further traffic needed for K06.
- CURRENT UI (user-confirmed final reload/setup): direct root K06, normal unprefixed RT/CP, runtime/custom-k06-pass-through.py, timeout2000, q/w/default regex; templates/CheckPage/custom/two automatics ON, AutoFollow/Intercept OFF. Cached fixture sid/token k00-workflow.1. Separate burp_k06_probe.py helper remains loaded (its private resources closed). Confirm/reset settings before K07; do not assume all OFF.
- K06 gated fixture18770 running PID10008, stdout/stderr and raw captures ignored under runtime. Fixture self-test passes; wrapper standalone lifecycle/file-command smoke passes 10 checks. Generated custom-k06-cases.py has only a finite 1.5s CheckPage gate with 2000ms timeout, never infinite code. Test wrapper limits traffic to tagged127.0.0.1 ports18765/18770 and has an instance-scoped file command channel; none of this channel is in production source.
- Additional E56 K06 subset passes in one isolated JVM: eight full source/UI cycles, four finite custom successes/four finite timeouts; all publishers/listeners/coordinators close and workers naturally finish without accumulation (jython-lifecycle.json). This is not a full memory/load proof.
- Instrumented instance was removed for the user's first direct-entry reload. Do not run another wrapper scenario or file command; the current main is direct entry. Standalone smoke and actual wrapper share channel filenames, never run them together.
- Inspection established native editor documents can be observed and request/response references match. The temporary helper produced a native UI NullPointerException; the trace does not establish a main-extension fault. Its controller fixture was improved but not rerun; helper removal was confirmed. Preserve the inspection attempts under K06.
- [K06 evidence and precise coordination/recovery limits](docs/stabilizacios-terv/eredmenyek/K06/README.md), environment.json and closure.json are the handoff. K07 not started. The requested Git checkpoint includes source, test helpers and synthetic evidence; generated runtime files stay ignored. Closure JSON records the validation-time Git state, before this checkpoint. One-shot edit scripts/temporary source removed; final source-only patch reverse-check and diff-check pass (only autocrlf notices).

## Prior K05 (2026-10-31)

- User authorized K05 after delegating D08. Base is pushed K04 `09c0346`; pre-existing own D08 documentation was preserved. Source marker K05, SHA-256 `92F2450F8F265B05811D2027A5E590D51FAE920FADC81DB729CC65B999C5EB91`.
- Bounded CustomExecutor: one worker/one pending, submission deadline includes compilation/exec/call/conversion. Shared JVM bootstrap Class monitor + fixed ThreadGroup prevents reload worker accumulation across PythonInterpreter instances. No hard interruption/sandbox/CPU bound. P13 fixed; P14 remains explicitly accepted, reproduced limitation. Test uses Swing Timer, config-version discard and close guards; code/enabled/timeout freeze across RT/CP. Other settings/session coordination stays K06.
- CPython/Jython: 144 cases, 143 pass, 1 known/accepted hard-stop limitation. Full API/Swing import, standalone and actual-Burp native helper (13 executor cases +13 checks) pass. Infinite Python and native Java await tested ONLY in externally bounded disposable JVMs, both pass bounded-capacity checks and child cleanup.
- Actual user loaded root K05 and helper, all OFF/Intercept OFF; then confirmed each wire configuration. All eight wire cases pass: normal, exception, bad-result, top-timeout50, function-timeout200, post-RT CP-timeout200 (one action/DROP), invalid timeout abc, and finite concurrency (2 template POSTs + 1 original fallback, 2 serialized calls on 1 worker). Concurrency used CheckPage OFF; global session pairing is not claimed. User also confirmed main Test showed CUSTOM_TIMEOUT; manual UI responsiveness was not separately stated (native EDT checks pass).
- K05a closed in chosen D08 scope. Final actual remove/reload confirmed, only root K05 loaded; normal unprefixed RT/CP plus runtime/custom-k05-pass-through.py, timeout2000, q/w/default regex; template/CheckPage/custom/two automatics ON, AutoFollow/Intercept OFF. Final 1-action/2-request/exactly2-call custom regression passes with raw payloads, correct cookie/token, first token None. Native worker changed 269→291 and stayed one per group. Cache sid/token k00-workflow.1; helper removed. No manual K05 gate remains. [K05 evidence/current state](docs/stabilizacios-terv/eredmenyek/K05/README.md).
- User requested a separate K05 commit/push checkpoint; its revision is in Git history. K06 not started. Runtime captures/generated code ignored. Loopback18765 fixture confirmed available. No infinite custom code was run inside Burp. Keep prior failed/helper attempts with their actual hashes and failure reasons.

## D08 decision (historical prerequisite, 2026-10-31)

- K04 committed/pushed as `09c0346`. User subsequently reported fresh latest main BoberProxy, all extension options OFF; Burp Intercept/helper presence was not separately reconfirmed.
- User asked what D08 means and delegated the choice to the assistant. Selected K05a bounded in-process execution: one worker, at most one waiting job, 500 ms default / integer 1–30000 ms, submission-to-completion monotonic budget including compile/exec/call and queue wait. Timeout returns a visible failure, discards late owned results and never replaces a still-running worker; unload/reload must not accumulate old workers. Preserve Jython/Java imports and two independent custom calls.
- Hard interruption/CPU bounds and sandboxing are explicitly not promised; a stuck worker may need Burp restart. P14 is not automatically fixed by bounded capacity. See [D08](docs/stabilizacios-terv/03-mukodesi-dontesek.md#d08--custom-végrehajtás-és-valódi-megszakítás). Decision/documentation only so far; no K05 implementation or traffic was started.

## Prior K04 (2026-10-31)

- K03 committed/pushed as `406a609`; clean entry. User authorized K04 and confirmed fresh direct BoberProxy with all options OFF. D06 global shared jar/token and its cross-target/Path/Secure limitation explicitly accepted; D05/D14 deletion, empty values and token lifecycle also accepted (two answers choosing option 1).
- K04 closed in the tested environment: exact cookie fields, UTC expiry/Max-Age precedence, tombstones/readdition/Clear, byte-preserving manager inputs, CSRF compile/validation on document edits. No full workflow coordination claim: per-workflow state and Clear during network wait remain K06. Read [K04 evidence/current state](docs/stabilizacios-terv/eredmenyek/K04/README.md) before traffic.
- Final CPython/Jython: 131 cases, 129 pass, 2 known K05 defects. Full API/Swing import and 22 standalone native checks pass. First Jython logic attempt had a test-only high-byte Unicode-literal failure, retained separately.
- First actual K04/helper PASS21 and all 26 traffic cases passed (26 actions/71 target requests, source D900...). Every UI gate was confirmed. A final review found oversized regex repetition could escape as OverflowError; the only further source change adds that exception to the regex-config handler. Final source `15869D95FCA0C8EC91B1D6BE4EDEDB1897499A384E90CD7832493FBD0DD9159E`; both logic runtimes pass, standalone native22 passes. Earlier evidence is preserved as before-overflow-guard; traffic reports keep their actual earlier hash.
- Final root reload and actual helper PASS22 confirmed. The final normal custom regression passed with 1 action/2 requests/exactly2 custom calls, raw payloads and correct cookie/token; initial token None after Clear. No manual K04 gate remains. Current UI: normal unprefixed RT/CP, runtime/custom-k04-pass-through.py (2000ms), template/CheckPage/custom/two automatics ON, q/w/default regex; AutoFollow/Intercept OFF. Cache sid/token k00-workflow.1; helper still loaded. Loopback servers:18769 PID5740 and18765 PID10172; runtime captures ignored. User requested a separate K04 commit/push checkpoint; its revision is in Git history. K05 not started. D08 must be finalized before K05, especially bounded workers versus guaranteed isolation/cancellation.

## Stabilization Work In Progress (2026-10-30)

### Current K03

- K02 was committed/pushed as `1042978`. The user then removed all extensions, loaded only current K02, confirmed all options/Intercept OFF, and authorized K03. Worktree was clean on entry.
- K03 closed in the tested environment: [K03 evidence](docs/stabilizacios-terv/eredmenyek/K03/README.md). Source SHA-256 `37BC16019A13EDEDB0E4BBD9C982EB2905AC139F63E82408560F0D2269B87370`; marker `BoberProxy loaded (stabilization K03)`. CPython/Jython: 99 cases, 93 pass, 6 later defects. Full API/Swing import and native interfaces pass. Deadline is a shared 30000 ms scheduling budget, not cancellation of a blocking API call.
- User loaded Before guard, actual K03 and After observer, all options/Intercept OFF. Native real-Burp probe now passes 10 checks, including two real finite blocking calls with a 100 ms isolated test budget. Earlier 9/10 attempts were fixture-tracking/stale-listener issues and are retained. Fixture ports 18766/18767 HTTP, 18768 local TLS; Windows exclusive bind now prevents stale versions sharing ports.
- Separate-extension action probes are retained with their topology limitation. The user now loaded only burp_k03_instrumented.py: the same unchanged main source runs between before/after traces on one real message. Native PASS 10 and wrapper registration smoke passed. All four passive action cases, both manual request/response Forward pairs (options OFF and active/unmatched), and matched automatic forwarding with Intercept ON passed. No broad third-party-extension compatibility claim is made.
- Instrumented live checks now pass: three manual request/response Forward pairs (including cookie/CSRF collection verified in the next RT), passive/unmatched action matrix, active automatic forward, and all eight redirects (off, relative, chain10, chain11, loop, invalid, cross-port, cross-scheme). TLSv1.3 was observed; CP returned to the original service. Wrong-/echo-template OFF attempt and test-assessment failures remain archived.
- Final direct entry also passed: user removed the instrumented wrapper, loaded BoberProxy.py directly, restored normal unprefixed HTTP fixtures on 18765 plus custom-k03-pass-through.py, and confirmed setup. The final legacy-normal request had one RT action/one CP, exact raw payloads, correct cookie/CSRF, exactly two custom calls and empty initial token. No K03 confirmation is pending; K04 has not started. The user requested a separate K03 commit/push checkpoint before K04; revision is in Git history.
- Current Burp state: only direct K03; normal unprefixed RT/CP fixtures, runtime/custom-k03-pass-through.py, template/CP/custom/cookie/CSRF ON, timeout 2000 ms, q/w/default regex; AutoFollow and Intercept OFF. Cached normal-fixture sid/token end in k00-workflow.1. The old 18765 and K03 18766/18767/18768 loopback fixtures were left available. The private TLS test key stays ignored in runtime. Confirm live settings before K04.

### Prior K02 handoff (historical)

- K00/K01 were committed and pushed as `04d6398` on `origin/main`; the worktree was clean on K02 entry. The user authorized continuation and confirmed all options OFF.
- K02 is closed in the tested Burp environment: [K02 evidence](docs/stabilizacios-terv/eredmenyek/K02/README.md). Current source SHA-256: `2A5E783AB7B34BE8CD3D49909E5DAED755E2DF1DBD994F6C02A8B0DD83A103E9`; startup marker `BoberProxy loaded (stabilization K02)`. CPython/Jython: 74 cases, 65 pass, 9 known later-round defects. Native byte tests and full API/Swing import pass for that hash.
- All eight template traffic scenarios and active unmatched controls passed on the preceding B80A... candidate; the user copied the original custom diagnostic. The after-RT failure had an empty initial token, exactly one action and DROP. Reports are retained under K02/before-bodylen-display.
- A final E12 gap was fixed: unknown body length now renders blank instead of zero. The user confirmed the final main/helper reload and setup, then all eight template scenarios and five active unmatched controls passed again for the final hash; 23 actual-helper/Swing checks pass. No K02 manual confirmation remains pending. K03 has not started. The user requested a separate K02 commit/push checkpoint before continuing in a later round; its revision is recorded in Git history.
- Current Burp state: K02 loaded, both normal HTTP fixtures and generated custom-k02-cases.py; template injection, CheckPage, custom and cookie/CSRF options ON, timeout 2000 ms; AutoFollow and Burp Intercept OFF. The last request was the normal successful workflow; cached fixture cookie/token remain. The separate no-traffic helper extension may still be loaded and can be removed. Confirm settings before K03 traffic.
- K02 traffic uses generated `tests/stabilization/runtime/custom-k02-cases.py`, never `.py.in`. `prepare_k02.py` also generates the exact K01 framing baseline. Read K02 evidence and wait for UI confirmation before traffic.

### Prior K00/K01 handoff (historical)

- The user authorized execution of the [stabilization plan](docs/stabilizacios-terv/README.md). K00 and K01 are recorded as complete in the tested environment; K02 has not started. The running Burp has K01 loaded.
- Reusable helpers now exist under [tests/stabilization](tests/stabilization/README.md). The original snapshot below is historical.
- The archived K00 CPython/Jython baseline has 10 passing compatibility cases and 14 known defects. The current [K01 candidate](docs/stabilizacios-terv/eredmenyek/K01/README.md) has 51 cases: 39 passing and 12 remaining known defects on both runtimes. P02/P04 are now passing regressions; expected failures are not fixed acceptance cases.
- The user confirmed Burp Community loading and the request/response viewer. Real passive, Request Template, cookie/CSRF-enabled CheckPage, and two-call custom pass-through traffic succeeded against the loopback fixture.
- K01 real failure traffic also passed: empty CheckPage preflight, controlled post-build failure, and connection-close-after-acceptance each have target-side counters and explicit terminal outcomes. Burp may return its extension-drop error page with HTTP 200; status alone is not success.
- K01 source SHA-256 is `3BF88A21442683C6135895125AAC49AC09BD52A31BE13B9FF75DAAF8FCDFB111`; its source-only patch is archived with the K01 results. The user requested a Git commit/push checkpoint of K00/K01, including the plan, test helpers and evidence. See the K01 result page for the exact current UI state before sending further requests.
- Current results, incomplete checks, and active manual configuration requests are tracked in the [K00 evidence](docs/stabilizacios-terv/eredmenyek/K00/README.md) and [execution log](docs/stabilizacios-terv/05-vegrehajtasi-naplo.md). Read these before sending traffic: proxy/UI settings change between scenarios.
- The fixture listens only on `127.0.0.1:18765`; Burp listens on `127.0.0.1:8080`. Generated runtime captures are ignored by Git. Do not auto-repeat a request after uncertain delivery.
- Use exact visible checkbox/editor labels in requests to the user (for example `Use CheckPageTemplate` and `Injecting proxy from templates`), not unexplained `CP` or `atiras` shorthand. Keep manual setup requests focused.

## Snapshot

Repository snapshot reviewed on 2026-05-08.

Observed top-level files:

- `BoberProxy.py`
- `README.md`
- `AGENTS.md`
- `AI_NOTES.md`
- `CHANGELOG.md`

No packaging files, dependency manifests, or automated tests were present at review time.

## High-Confidence Understanding

- This is a Burp Suite extension implemented as a single Jython-oriented Python file.
- The extension registers Burp listeners and adds a custom UI tab.
- Core behaviors appear to include logging, filtering, request templating, cookie handling, CSRF extraction, redirect following, and custom payload transformation.

## Assumptions

- Assumption: `BoberProxy.py` is the intended extension file to load in Burp.
- Assumption: The runtime target is Jython 2.7.x or a very similar compatibility layer.
- Assumption: The project is maintained through manual testing in Burp rather than automated CI.
- Assumption: The current repository is intentionally minimal, not accidentally incomplete.

## Unverified Items

- Unverified: the extension loads successfully in the current Burp + Jython environment
- Unverified: the README setup instructions are fully current
- Unverified: the custom code execution timeout and thread behavior are stable under real load
- Unverified: request rewriting behaves correctly for all content types and parameter layouts
- Unverified: redirect-following behavior preserves all headers needed in real workflows
- Unverified: there are no external local files normally used during development but absent from this repo

## Notable Risks

- Single-file architecture means small edits can have broad side effects.
- Many broad exception handlers may hide errors and make regressions hard to spot.
- The custom code path uses `exec(...)`, which is powerful but operationally risky.
- UI code and network workflow logic are tightly coupled inside `LoggerUI`.
- The README references `BoberProxy_final_v1.py`, but that file is not present in the repository.

## Suggested Safe Validation Strategy

- Prefer documentation changes first, then narrowly scoped code changes.
- When code edits begin, validate extension load in Burp before deeper functional testing.
- Test proxy-off behavior separately from proxy-on templating behavior.
- Test cookie and CSRF updates on both response interception and internal redirect/request flows.
- Exercise the custom codeblock path with both valid and intentionally failing user code.

## Next Steps

1. Confirm the intended extension filename and decide whether the README mismatch should be corrected later.
2. Verify the expected runtime matrix: Burp version, Jython version, and whether Python 2 syntax is a hard requirement.
3. Run a manual smoke test in Burp covering load, UI render, passive logging, and proxy toggle behavior.
4. If active development continues, consider carving out a few behavior-focused notes or pseudo-tests for cookies, CSRF extraction, and template rewriting.
5. If maintainability becomes a goal, plan a staged refactor that separates UI, request building, and state managers without changing behavior first.

## Pointers Into The Code

- Entry point: `BoberProxy.py` `BurpExtender.registerExtenderCallbacks(...)`
- UI hub: `BoberProxy.py` `LoggerUI`
- Proxy rewrite workflow: `BoberProxy.py` `proxy_flow_process_request(...)`
- Request template construction: `BoberProxy.py` `build_request_from_template(...)`
- User transform execution: `BoberProxy.py` `run_user_code(...)`
- Redirect logic: `BoberProxy.py` `_follow_redirects_chain(...)`

## Change Policy For Future AI Contributors

- Do not assume modern Python tooling exists here.
- Do not rewrite large portions of `BoberProxy.py` without a behavior-preserving plan.
- Clearly label assumptions in any future handoff note or PR-style summary.
- If adding tests later, keep them clearly separated from the Burp/Jython runtime path.
