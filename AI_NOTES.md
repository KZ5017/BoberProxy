# AI_NOTES.md

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
