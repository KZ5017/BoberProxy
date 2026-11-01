# AGENTS.md

## Purpose

This repository contains a single-file Burp Suite extension written for a Jython-compatible Python runtime. The current goal of this file is to help future Codex or human contributors make safe, low-friction changes without needing to rediscover the repository shape.

## Repository Scope

- Main implementation: `BoberProxy.py`
- Bundled optional code-editor dependency: `lib/rsyntaxtextarea-3.6.3.jar`, provenance/license in `lib/README.md`
- Main user documentation: `README.md`
- Handoff notes for AI contributors: `AI_NOTES.md`
- Change log for repository-level documentation updates: `CHANGELOG.md`

## What The Project Does

BoberProxy is a Burp Suite extension that:

- logs accepted HTTP traffic in a custom UI tab, with metadata in memory and full content in an owned temporary archive
- optionally intercepts and rewrites proxied requests from templates
- manages cookies and CSRF tokens
- optionally follows redirect chains
- executes user-provided Python transformation code against payload values

## Working Assumptions

- The extension is intended to run inside Burp Suite through the Extender Python integration.
- Production targets Jython 2.7 syntax. The recorded environment is Burp Community 2026.10.1, Jython 2.7.4 and Java 26.0.2 on Windows.
- Validation combines source-logic tests, standalone native/Swing probes, private helpers in actual Burp and directed loopback traffic. Manual loading/UI confirmation is still required.

The environment above has live integration evidence under `docs/stabilizacios-terv/eredmenyek`. It is not a compatibility claim for other versions. Read the latest `AI_NOTES.md` section for the current loaded version and switches; earlier sections are historical snapshots.

## Important Code Areas

- `BurpExtender.registerExtenderCallbacks(...)`: Burp entry point
- `BurpExtender.processHttpMessage(...)`: passive HTTP logging hook
- `BurpExtender.processProxyMessage(...)`: request/response proxy interception hook
- `LoggerUI`: UI construction and most operational workflow logic
- `CookieManager`: cookie parsing and injection
- `CsrfManager`: CSRF extraction and cached token storage
- `run_user_code(...)`: custom transform execution path
- `build_request_from_template(...)`: request templating path
- `proxy_flow_process_request(...)`: high-level proxy rewrite workflow
- `_follow_redirects_chain(...)`: redirect handling
- `RuntimePublisher` / `SessionCoordinator`: immutable configuration publication and workflow ownership/Clear generations
- `CaptureFilterPlan` / `DisplayFilterPlan` / `FilterWorker`: admission/display filtering and bounded Java-regex work
- `LogArchive` / `RawLogBudget` / `LogIoWorker`: owned content storage, raw snapshot reservations and guarded background reads

## Guardrails For Future Edits

- Preserve Jython compatibility unless the project is explicitly being migrated.
- Distribute the bundled `lib/` folder with the Python source. Load code-editor classes/themes outside the EDT, create widgets on it, and avoid global UIManager/keymap resets. Keep the editor's own anonymous keymap/action map: shared RSTA caches can retain another extension loader's actions. Missing dependencies must retain the basic editor with a visible warning.
- Avoid introducing Python 3-only syntax into `BoberProxy.py` without confirming runtime expectations.
- Treat broad `except:` blocks as behavior-sensitive areas; refactors there can change extension stability.
- Treat the custom-code execution path as high risk because it uses `exec(...)`.
- Test Burp loading behavior after any code edits, even if the change seems documentation-only adjacent.
- `BoberProxy.py` declares Latin-1 and uses CRLF. Preserve its bytes/line endings; do not accidentally rewrite it as UTF-8. Documentation and new tests use UTF-8.
- Preserve raw payloads, explicit wire conversion and one-time marker replacement. Do not infer a new target from a template Host header, auto-decode values or change GET redirect policy while cleaning up.
- Never replay a possibly accepted workflow as a transport fallback. Record target-side request/action counters as well as client results.
- Finite custom/regex capacity is not a sandbox or hard cancellation. Infinite/expensive probes run only in disposable, externally bounded JVMs, never in the user's main Burp process.
- Own archive files must be reclaimed only through their ownership/read-pin lifecycle. Do not delete an arbitrary temporary directory or do disk I/O on the EDT.
- For actual Burp tests use the root source plus the requested private helper. Instrumented wrappers have scoped loopback/file channels; never run their standalone controller concurrently with a loaded live wrapper sharing channel files.
- Generated `tests/stabilization/runtime/*.py` custom fixtures are copied into the custom editor. Their `.py.in` templates are not directly usable. Runtime captures stay ignored; archive only synthetic evidence.

## Known Risks

- The repository is a single large source file, which increases regression risk.
- Disabled/unmatched Proxy traffic preserves its received interception action. Active rewrites forward automatically; pre/post-send failures have different fallback/drop behavior.
- Global cookies/single CSRF token intentionally have no Domain/Path/Secure isolation. Workflow-local coordination does not remove this accepted cross-target limit.
- Arbitrary custom code and pathological Java regexes cannot be forcibly stopped reliably. Bounded workers prevent replacement-worker accumulation, but restart can be necessary.
- The raw log snapshot budget is not a total heap/RSS or metadata limit. Full K11 load/memory acceptance is separate from prior finite probes.

## Recommended Handoff Workflow

1. Read `AI_NOTES.md` first for assumptions, open questions, and next steps.
2. Read `README.md` for intended behavior and user-facing setup flow.
3. Inspect `BoberProxy.py` around the specific workflow being changed rather than scanning the entire file.
4. Prefer narrow changes and preserve behavior unless an explicit refactor is requested.
5. If code changes are made later, record them in `CHANGELOG.md`.

## Verification Boundaries

- Root loading and directed redirect/cookie/CSRF/custom/logging behavior have actual Burp evidence in the recorded environment. Preserve actual source hashes and failed attempts; never relabel old reports as a newer candidate.
- Other Burp/Jython/Java versions and full HTTP/2 behavior have not been established by the HTTP/1.x loopback fixtures.
- Full final long-run/load/memory matrix is tracked in K11. Existing results are scoped measurements, not a general throughput or deterministic GC guarantee.
