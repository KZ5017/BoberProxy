# AGENTS.md

## Purpose

This repository contains a single-file Burp Suite extension written for a Jython-compatible Python runtime. The current goal of this file is to help future Codex or human contributors make safe, low-friction changes without needing to rediscover the repository shape.

## Repository Scope

- Main implementation: `BoberProxy.py`
- Main user documentation: `README.md`
- Handoff notes for AI contributors: `AI_NOTES.md`
- Change log for repository-level documentation updates: `CHANGELOG.md`

## What The Project Appears To Do

BoberProxy appears to be a Burp Suite extension that:

- logs HTTP traffic in a custom UI tab
- optionally intercepts and rewrites proxied requests from templates
- manages cookies and CSRF tokens
- optionally follows redirect chains
- executes user-provided Python transformation code against payload values

## Working Assumptions

- The extension is intended to run inside Burp Suite through the Extender Python integration.
- The target Python dialect is Jython-oriented and closer to Python 2 than modern CPython 3.
- Manual testing inside Burp is the primary validation path.

These assumptions are based on repository contents and have not been fully verified in a live Burp environment.

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

## Guardrails For Future Edits

- Preserve Jython compatibility unless the project is explicitly being migrated.
- Avoid introducing Python 3-only syntax into `BoberProxy.py` without confirming runtime expectations.
- Treat broad `except:` blocks as behavior-sensitive areas; refactors there can change extension stability.
- Treat the custom-code execution path as high risk because it uses `exec(...)`.
- Test Burp loading behavior after any code edits, even if the change seems documentation-only adjacent.

## Known Risks

- The repository is a single large source file, which increases regression risk.
- The README installation example references `BoberProxy_final_v1.py`, while the repository contains `BoberProxy.py`.
- The README warns that proxy interception behavior may conflict with Burp's built-in intercept flow.
- There is no automated test suite in the repository.

## Recommended Handoff Workflow

1. Read `AI_NOTES.md` first for assumptions, open questions, and next steps.
2. Read `README.md` for intended behavior and user-facing setup flow.
3. Inspect `BoberProxy.py` around the specific workflow being changed rather than scanning the entire file.
4. Prefer narrow changes and preserve behavior unless an explicit refactor is requested.
5. If code changes are made later, record them in `CHANGELOG.md`.

## Explicitly Unverified

- Live loading in Burp Suite
- Exact Jython version compatibility
- Redirect, cookie, and CSRF behavior against a real target
- Whether all documented UI features still match current runtime behavior
