# BoberProxy

**Payload transformations and stateful HTTP workflows for command-line tools routed through Burp Suite.**

BoberProxy lets tools such as sqlmap, sstimap and ffuf drive an application's HTTP workflow through Burp Proxy. It takes selected parameter values from eligible in-scope requests, optionally transforms them with Python, and inserts them into a complete request template. Cookie and CSRF automation tracks state changes between requests. An optional **CheckPage Template** retrieves the result from another known endpoint within that scope and returns that response to the tool.

This is useful when a tool can generate the right payloads, but needs help delivering them in the application's required format, maintaining a rotating session, or evaluating an effect that appears somewhere other than the submission response.

<p align="center">
  <img width="767" height="512" alt="BoberProxy" src="https://github.com/user-attachments/assets/53abcb60-e218-4153-823f-d5c2a2f902d0" />
</p>

## Contents

- [What it does](#what-it-does)
- [Installation](#installation)
- [First request](#first-request)
- [BoberProxy scope](#boberproxy-scope)
- [Request workflows](#request-workflows)
- [Custom Python transformations](#custom-python-transformations)
- [Cookies and CSRF](#cookies-and-csrf)
- [Logging and filters](#logging-and-filters)
- [Interface](#interface)
- [Troubleshooting](#troubleshooting)
- [Validation and boundaries](#validation-and-boundaries)
- [Development and license](#development-and-license)

## What it does

- **Adapt a tool's requests:** build requests from a template, with up to two incoming payload values and a CSRF token.
- **Transform payloads:** use a Python editor with syntax highlighting, line numbers, indentation, undo/redo and a local Test action.
- **Select one application:** configure BoberProxy's own origin/path scope before activating templates or collecting session state. Other Proxy traffic passes through.
- **Track rotating state:** collect cookies and a CSRF token from responses, then use them in subsequent generated requests.
- **Read results elsewhere:** submit through Request Template, then fetch through CheckPage Template. This supports workflows such as stored template injection, where the effect appears on a different page.
- **Inspect traffic:** log response-bearing HTTP exchanges, inspect captured requests/responses in Burp-native viewers, and apply separate capture and display filters.

**Template rewriting applies to traffic passing through Burp Proxy.** The logger can also receive HTTP responses from other Burp tools; seeing a Repeater or Intruder exchange in the log does not mean that its request was rewritten. Tool availability depends on the Burp edition.

## Installation

### Requirements

- Burp Suite with Python extension support.
- A Jython standalone JAR. The verified runtime is **Jython 2.7.4**; custom code uses Python 2.7 syntax and the libraries available to that runtime.
- The complete BoberProxy package, including the bundled `lib/` directory for the enhanced code editor.

The recorded integration environment is **Burp Suite Community 2026.10.1, Jython 2.7.4, Java 26.0.2 on Windows**. The results do not establish compatibility with other editions or runtime versions.

### Load the extension

1. Clone the repository or extract its complete ZIP. Keep this structure:

   ```text
   BoberProxy.py
   lib/
     rsyntaxtextarea-3.6.3.jar
     RSyntaxTextArea-LICENSE.txt
   ```

2. In Burp **Settings → Extensions → Python environment**, select the Jython standalone JAR.
3. Open **Extensions → Installed → Add**, choose **Python**, and select the root `BoberProxy.py`.
4. Open the **BoberProxy** tab. Check the extension's **Output** and **Errors** panes for loading problems.

The editor library is already included and loaded locally. Do not install its JAR as another extension or add it to the Java classpath. If it cannot be loaded, BoberProxy falls back to a basic text editor and displays a warning. Restore the complete package and reload to recover the enhanced editor.

When reloading, remove the old BoberProxy instance first so that only one main instance remains. Files under `tests/stabilization/` are development helpers, not the extension to install. Older Burp interfaces may label the extension settings **Extender**.

## First request

Start with a single request and confirm what reaches the application before starting a fuzzing run. Substitute your own host, endpoints and required authentication headers for the illustrative `app.test` example below.

1. Configure the command-line tool to use your Burp Proxy listener, for example `127.0.0.1:8080`. For HTTPS, configure the tool to trust Burp's CA as required by that tool.
2. Leave **Burp Intercept OFF** for unattended traffic. A new BoberProxy instance starts with template injection, custom code, CheckPage and both state automations disabled; logging is enabled.
3. Open **BoberProxy scope**. Set **Target origin** to `http://app.test` and leave **Path prefix (optional)** empty for this example; click **Apply**. The injection switch becomes available but stays OFF.
4. Put a complete working request in **Request Template**, replacing the values you want to control with the markers shown here:

   ```http
   POST /submit HTTP/1.1
   Host: app.test
   Content-Type: application/x-www-form-urlencoded

   value=p4yl04dm4rk3r&extra=53c0undm4rk3r
   ```

5. Keep **Payload 1 parameter** as `q` and **Payload 2 parameter** as `w`. Enable **Injecting proxy from templates**. Leave **Use CheckPageTemplate**, **Use custom codeblock** and the cookie/CSRF automations OFF for this first request.
6. Have the tool send a proxied request to `http://app.test/entry?q=HELLO&w=SECOND`.

BoberProxy takes `HELLO` and `SECOND` from the incoming request and builds the template request. The application receives `POST /submit` with `value=HELLO&extra=SECOND`; the tool receives that request's response. The builder updates `Content-Length` when rebuilding the message.

The incoming URL must select the configured server, scheme and port. **Changing only the template's `Host` header does not change the network destination.** Generated requests must have a matching `Host` authority and an allowed path; mismatches are rejected before that send.

Once this works, enable only the additional features your workflow needs: custom transformation, rotating cookie/CSRF state, or CheckPage.

## BoberProxy scope

**BoberProxy scope** selects one exact `http://host[:port]` or `https://host[:port]` origin, with an optional path prefix. It is independent of Burp Target scope and log filters. A fresh instance has no scope: template injection is OFF/disabled, and cookie/CSRF automation collects nothing until a scope is configured. Logging remains available.

- Scheme, canonical host and effective port must match. Default ports 80/443 are recognized; host comparison does not resolve DNS aliases. `localhost` and `127.0.0.1` are different targets. There are no wildcard, regex or multi-host scopes.
- An empty path prefix or `/` allows all paths on that origin. `/admin` allows `/admin` and `/admin/...`, but not `/administrator`; matching is case-sensitive and ignores the query. Prefix checks conservatively reject ambiguous encoded separators, backslashes and dot segments. Wire payloads are not normalized or decoded by this check. The permitted paths must cover the incoming carrier URL, both templates and any endpoint used to seed cookie/CSRF state.
- Original out-of-scope requests pass through without BoberProxy transformations or session collection, preserving their received interception action. They may still be logged. This is not a network firewall.
- Template `Host` headers and absolute request authorities must agree with the actual service. Request Template, redirects and CheckPage each need permission before dispatch; a template cannot retarget the connection.

**Apply** changes the active scope only after validation. A changed scope clears both managed stores and cookie-deletion markers, switches injection OFF, clears AutoFollow selection and invalidates old workflows. Re-enable injection deliberately after checking the templates, and reselect AutoFollow if needed. Applying an equivalent scope keeps the existing state; **Cancel** leaves it unchanged. **Clear scope** clears state and disables injection. Scope is per instance and is not persisted across reloads.

An already authorized request may finish against its frozen old target. After replacement, its late response cannot populate the new state, and its workflow cannot obtain permission for another send. Arbitrary custom code, Burp session rules, other extensions and a tool's own requests remain outside this guard's control.

## Request workflows

### Two delivery modes

For an eligible matching request with valid templates:

| Setting | Requests sent | Response returned to the tool |
| --- | --- | --- |
| **Use CheckPageTemplate OFF** | Burp sends the generated Request Template once through its normal Proxy path. | Request Template response. |
| **Use CheckPageTemplate ON** | BoberProxy sends Request Template internally, optionally follows its redirects, then hands the generated CheckPage request to Burp for forwarding. | CheckPage response. |

For a two-step workflow, populate **both** template editors before enabling CheckPage. For example, keep the submission template above and use this CheckPage template:

```http
GET /result HTTP/1.1
Host: app.test

```

Each eligible matching request now triggers a submission followed by a read of `/result`. The tool can evaluate the effect on that page directly. CheckPage may also contain payload or CSRF markers, and it uses state updated by the submission and any followed redirects.

Request Template and CheckPage use the original incoming request's network service and must satisfy the configured scope. Redirects resolve `Location` against the current request, but only allowed destinations are followed. A changed template `Host` header alone is not a routing mechanism.

### Parameter matching and markers

| Template marker | Value |
| --- | --- |
| `p4yl04dm4rk3r` | Payload 1, taken from the configured first parameter name; default `q`. |
| `53c0undm4rk3r` | Payload 2, taken from the configured second parameter name; default `w`. |
| `c5rfm4rk3r` | Current or custom-returned CSRF token, substituted only when **Auto-update CSRF** is enabled and a token is present. |

Matching uses parameter names and nonempty values in the incoming query string or an `application/x-www-form-urlencoded` body. The query is examined first; the first nonempty value found for each slot wins. JSON and multipart bodies are not additional payload sources. This restriction concerns the incoming carrier request: your template can still place payload markers in JSON, ordinary headers, paths or other request content. The generated path must remain in scope; the `Host` header must match the configured origin and cannot contain markers. Absolute request-target authorities must also match that origin. Give the two parameters distinct names; if their names are identical, the first slot has priority.

A request is eligible for rewriting when it passes BoberProxy's service/authority/path guard, template injection is ON and at least one selected payload value is nonempty. Burp Target scope does not grant this permission. Other proxied requests retain their normal behavior.

Payloads are preserved as raw values: `%252F+%2B` stays `%252F+%2B`. There is no automatic URL decoding or encoding. Markers are replaced once in the original template, including when they appear in headers or the body; inserted values are not searched again for markers. An absent payload slot contributes an empty value. Prepare any application-specific encoding in your custom transformation.

### Manual interception

BoberProxy preserves the interception action it receives from Burp when the request is outside its scope, template injection is disabled or the request does not match the payload parameters. Actively rewritten requests forward automatically. Disable **Injecting proxy from templates** when you want to review the original matching requests manually.

### Redirects and failure behavior

**AutoFollow redirect on RT** is available only while template injection and CheckPage are both enabled. It follows the internal Request Template's redirect chain, up to ten hops, with relative URL resolution and loop detection. Enabled cookie/CSRF automation processes the allowed target's received responses along the chain.

An out-of-scope redirect is a **neutral stop**: no request goes to its destination, the legitimate redirecting response may still update state, and a valid in-scope CheckPage continues. A malformed Location, transport failure, loop, hop limit or expired budget remains a workflow error. With CheckPage OFF, there is no extension-side redirect following; the original Request Template response, including a 3xx, is returned to the tool.

Follow-up redirect requests use the existing minimal **GET** policy, including after 307/308: they carry `Host`, `Connection`, the prior `User-Agent` when available, and enabled managed cookies. The original request body and `Authorization` header are not copied. Account for this when testing a redirect-dependent endpoint.

Workflow preparation, waiting for ownership, internal Request Template/redirect calls and CheckPage preparation share a **30-second scheduling budget**. This cannot forcibly interrupt a blocking Burp API call; after it returns, an expired budget prevents further steps. The final proxied exchange uses Burp's network timeout.

| Template preparation / internal-send failure | Result |
| --- | --- |
| Preparation fails before an internal send has been attempted | A diagnostic is shown and the original client request continues automatically, without the template rewrite. |
| Processing fails after an internal send has been attempted | The original request is dropped rather than replaying a possibly accepted operation. |

Scope replacement is a separate case: before any send, the original request retains its received interception action; after an internal attempt, the existing DROP policy applies. A failure while replacing the Proxy message also causes a DROP, including in Request Template-only mode; BoberProxy does not replay a partially handed-off request.

A preparation error is therefore not a guarantee that no request reaches the target. Check the diagnostic and actual request, especially when configuring a new template or custom function. Burp's extension-drop error page can itself have HTTP status **200**; that status alone does not establish workflow success.

## Custom Python transformations

Enable **Use custom codeblock** to run your function while building generated requests. The default is a pass-through:

```python
def custom_codeblock(payload1, payload2, csrf_token):
    return payload1, payload2, csrf_token
```

For example, to wrap the first payload in template-expression delimiters:

```python
def custom_codeblock(payload1, payload2, csrf_token):
    if payload1:
        payload1 = "{{" + payload1 + "}}"
    return payload1, payload2, csrf_token
```

The function must return a tuple or list of **exactly three values**, in that order. Return byte/text values or `None`; arbitrary objects, numbers and booleans are rejected. `None` means an empty payload; for the CSRF token it means no token, leaving its marker unsubstituted. Byte-valued text uses code points 0–255. Encode other characters explicitly, for example `u'\u20ac'.encode('utf-8')`.

In a successful two-step workflow with custom code enabled, the custom code executes **twice**: once for Request Template, then again for CheckPage using the original incoming payloads and the updated token. Top-level code also executes for each call in a fresh namespace. Keep side effects in mind, and do not rely on editor-level variables persisting between calls.

**Test** runs the function asynchronously with sample values, without BoberProxy sending an HTTP request. It still executes your code and any side effects that code performs. **Reset** restores the default function. Typing or resizing the editor does not execute code.

### Execution limits

The **Timeout (ms)** field accepts an integer from **1 to 30000**, default **500**. The per-call result deadline includes queue wait, compilation, top-level code, the function call and output validation. One worker executes custom code; at most one job can wait.

- `CUSTOM_TIMEOUT`: the result deadline expired.
- `CUSTOM_BUSY`: custom execution capacity is occupied.
- `CUSTOM_CONFIG_ERROR`: timeout configuration is invalid.

Custom code runs with Burp's Jython/Java permissions. **It is not sandboxed, and a timeout is not guaranteed forced termination.** A non-returning Python or Java operation can continue running and prevent further custom jobs, including replacement workers after reload. A Burp restart may be necessary.

A matched workflow uses the template, code, timeout and switch settings captured at its start. Ordinary UI edits affect later workflows. A scope change revokes the old workflow's permission instead of letting it finish further sends; a queued old custom job is rejected and a running result is discarded. An outdated Test result is discarded if its settings change before completion.

## Cookies and CSRF

BoberProxy maintains its **own cookie store and one CSRF token**. Burp cookie-jar rules and macros are not required for these features.

**Auto-update Cookies** and **Auto-update CSRF** each control both response collection and injection into generated requests. Collection covers scope-authorized Proxy responses and internal Request Template/redirect responses, with matching request provenance and scope generation. Logging a response from another Burp tool does not itself populate this state.

For a workflow requiring an initial authenticated session or token, enable the corresponding automation and let an in-scope initial response pass through Proxy before starting the tool; injection can remain OFF during collection. Use **Show Cookies** and **Show CSRF** to inspect what was collected. Keep any other required authentication data in your templates.

### Cookies

- Reads `Set-Cookie` headers and tracks updates and expiration/deletion.
- Managed values update the generated request's cookies; other template cookies are preserved.
- `Max-Age` takes precedence over `Expires`; nonpositive `Max-Age` or an expired date deletes a cookie.
- An empty value or the literal `deleted` is valid data by itself.
- A deleted cookie is also suppressed from the template until a new valid `Set-Cookie` restores it or **Clear Cookies** clears the store and deletion markers. Clearing allows the template's own cookie values again.

### CSRF

The **CSRF regex** uses Python/Jython regex syntax, with case-insensitive and DOTALL matching over the raw response. Its **first capturing group** supplies the token. The default looks for a `csrfmiddlewaretoken` input; adapt it to your application and place `c5rfm4rk3r` wherever the generated request needs the value.

An invalid regex or one without a capturing group produces a visible configuration error. No match retains the previous token; an empty capture is a present, empty token. **Clear CSRF** removes the token. **Reset to default** restores the regex. There is no separate manual token-entry control.

### State coordination and scope

Matched workflows are coordinated in sequence through their final Proxy response. Each uses a local cookie/token state for Request Template → redirects → CheckPage, so an unrelated passive response cannot substitute another token halfway through that sequence. **Clear Cookies** and **Clear CSRF** start a new shared generation, discarding old workflow publication while clearing only the selected kind of state. **Clear scope** clears both stores and disables injection.

**There is one cookie store and one token for the currently configured BoberProxy scope**, with automatic reset on scope replacement. This is not a browser-style cookie jar: individual cookie Domain, Path and Secure attributes do not provide additional isolation inside that scope. Choose a path prefix when the application boundary requires it; there are no saved or concurrent per-target session profiles.

Coordination cannot undo requests already handed to Burp or synchronize token changes caused by other clients. If the final response never arrives, workflow ownership stays reserved until Clear Cookies, Clear CSRF, a scope change or unload releases it. It is not a network-cancellation mechanism.

## Logging and filters

The log records HTTP exchanges when a response is available and capture rules accept it. Rows show time, host, method, path/query, status, **Total size** and **Body size** in bytes. Total size includes response headers; Body size excludes them. An empty body is `0`; an unknown body size is blank. Newest entries appear first by default, with stable IDs that are not renumbered after deletion.

Select a row to inspect its captured request and response. **Load from Viewer** can copy the captured request into a template. **Add selected to Site map** exports selected messages and also **adds their URLs to Burp target scope**. This does not change BoberProxy scope or grant template-rewriting permission.

### Capture filters: what gets stored

The sidebar's **1xx–5xx**, **Size Filter**, **Comparator**, **Value (bytes)** and **Response regex** controls govern new log admission. They do not decide whether Proxy requests are rewritten or forwarded.

Size filtering uses Total size or Body size. **Minimum** uses the smallest entered number, **Maximum** the largest, and **Not equal** excludes the listed byte values. Enter multiple numbers as a comma-separated list. If Body size is unknown, capture size filtering falls back to Total size. Response regex uses Java `Pattern.find()` with default flags over the complete raw response. Enabled criteria combine with AND; selected status classes are alternatives.

### Display filters: what is visible

The **Filter** dialog operates on stored entries without deleting their messages.

| Field | Matching rule |
| --- | --- |
| Host, Method, Status | Exact listed values. |
| Path | Listed substrings. |
| Body size | Listed integer byte counts. |
| ResponseContent | Java regex searches over response headers and body, case-insensitive and DOTALL. |

Enable a field with its checkbox. **eq** accepts a match to any listed value or pattern; **not eq** excludes matches. Active fields combine with AND. An active empty field rejects rows, including in `not eq` mode.

Enter **one regex per line** for ResponseContent. Commas in `a{1,3}` or `a,b` belong to that pattern. Other fields use comma-separated lists. Invalid regexes or numbers show a validation error and leave the last valid filter active.

These searches operate on byte-valued response text, without implicit character decoding or decompression. The Java logging/display regex engine and the Python CSRF regex engine are different. Java regex work has bounded capacity, but a pathological pattern cannot be forcibly stopped reliably and may require a restart.

### Storage, pause and clearing

Full captured request/response content is held in an owned temporary archive; memory primarily holds metadata. Content reads, writes and filtering run in background work. **Clear Selected**, **Clear Log** and unload release the extension's owned content asynchronously. They do not erase Burp's own history. The archive is for the current extension instance, not project persistence or crash recovery.

**Pause Logging** stops new log admission. Already accepted pending work may finish; template processing and cookie/CSRF automation are separate. Queue/byte saturation or an archive write error visibly pauses admission; inspect the diagnostic and use Pause Logging to resume after resolving the cause. Read/export errors are reported separately.

There is a shared **32 MiB budget for pending/active raw log snapshots** and finite work queues. This is not a total heap or process-memory limit: metadata grows with row count, viewers and conversion buffers consume memory, and the archive needs disk space.

## Interface

The main workspace contains **Viewer**, **Request Template** and **CheckPage Template** tabs, with the log beneath them. Request/response viewers start at equal widths; the dividers remain adjustable.

- **Sidebar width:** drag the sidebar's left divider leftward to widen it, or rightward back to its initial minimum. That minimum is measured from the startup font and controls.
- **Code editor height:** drag the grip below it up/down, approximately **6–29 lines**. Test/Reset and Output follow it; the sidebar scrolls vertically when needed.
- **Layout reset:** reloading restores the initial editor height and minimum sidebar width. Reload after a startup font/DPI change to recalculate the minimum.
- **Editor:** bundled RSyntaxTextArea provides Python highlighting, line numbers, four-space Tab input, automatic indentation, bracket matching and undo/redo. Long code/regex lines scroll horizontally within their fields. Highlighting does not change the Jython runtime or validate Python syntax.
- **Proxy settings:** the shortcut at the end of the tab row invokes Burp's native Proxy settings control. Availability depends on the host UI; a status message provides directions if unavailable.
- **Status strip:** the single row below the log remains visible independently of sidebar scrolling. **Logging enabled/paused** describes capture state, not whether a request is currently running. Longer messages are available in tooltips; the sidebar **Output** area shows custom results and diagnostics.

There is no separate log search box or next-match navigator. Use **Filter → ResponseContent** to search stored responses, or the message editor's own search within a selected message.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Traffic appears in the log but is not transformed | Configure BoberProxy scope; check origin/path and template Host, enable Injecting proxy from templates, send through Proxy, and check the selected nonempty query/form parameters. Capture filters do not enable rewriting. |
| Injection is disabled or switches back OFF | Apply a valid BoberProxy scope first. Activation also checks template authorities; a scope change intentionally resets injection and managed state. |
| Template activation fails or a generated request is rejected | Match the incoming service, BoberProxy scope, template Host/absolute authority and generated path. Editing Host does not retarget the connection; a destination mismatch prevents that generated send. |
| The tool evaluates the submission page instead of the result page | Enable Use CheckPageTemplate and fill its separate editor with the result-page request. |
| A cookie or CSRF token is missing | Configure the correct scope and enable its automation before collecting the initial in-scope Proxy response; inspect Show Cookies/Show CSRF, the regex capture, and the template marker. |
| Logging stops or rows seem missing | Check Pause Logging, capture rules, display rules, storage diagnostics and capacity counters. A display filter can hide stored rows. |
| A request appears to hang | Check Burp Intercept, pending session ownership, custom execution and other Burp rules/extensions. A missing final response or non-returning custom job can block later work. |
| A failure returns HTTP 200 | Read BoberProxy's Output/status and response body: Burp can return an extension-drop error page with status 200. |
| The editor has no highlighting or line numbers | Restore `lib/` beside the root Python file and reload; inspect the dependency warning. |

## Validation and boundaries

The stabilization work covers request delivery, byte handling, state coordination, bounded custom/regex work, logging/archive lifecycle and UI behavior. The [K11 report](docs/stabilizacios-terv/eredmenyek/K11/README.md) and [E01–E63 matrix](docs/stabilizacios-terv/eredmenyek/K11/matrix.md) record actual results, source hashes, failed attempts and measurement limits.

That baseline includes actual Burp regression and directed HTTP/1.x traffic, three dedicated 1k/10k/100k load-and-memory runs, a **30-minute mixed run with 45,000 client requests**, and a separate **5-minute fault run**. The later [editor-height](docs/ui-vezerlopanel-eredmenyek/UI04/README.md) and [sidebar-width](docs/ui-vezerlopanel-eredmenyek/UI05/README.md) changes have their own native and manual Burp checks; the full K11 load run was not repeated for those UI changes.

The reports are scoped evidence, not a universal throughput or compatibility guarantee. The old isolated callback baseline is unavailable, so the original relative callback-performance gate cannot be assessed. Dedicated body-retention tests do not attribute the entire Burp heap to the extension. Full HTTP/2 behavior and other runtime versions have not been established by these HTTP/1.x checks.

The [Target Scope evidence](docs/target-scope-eredmenyek/README.md) separately records the later guard implementation: CPython/Jython regressions, native/actual Burp UI checks, directed A/B/HTTPS traffic, controlled scope changes and same-message manual interception. The full K11 long-run workload was not repeated for this change.

The operational boundaries to keep in mind are the **single-scope cookie/token model**, **raw byte handling**, **pre-send original-request fallback**, **minimal GET redirect policy**, **temporary log storage**, and **absence of guaranteed forced termination for custom code or Java regexes**, described above.

## Development and license

The runtime implementation is [BoberProxy.py](BoberProxy.py); the editor dependency is bundled under [lib/](lib/README.md). Development and verification material is separate from normal installation:

- [Test tools and usage](tests/stabilization/README.md)
- [Stabilization plan and execution history](docs/stabilizacios-terv/README.md)
- [Changelog](CHANGELOG.md)
- [Contributor guardrails](AGENTS.md)

BoberProxy declares the **MIT License**. The bundled **RSyntaxTextArea 3.6.3** library is distributed under **BSD-3-Clause**; its provenance and complete upstream license are included in [lib/README.md](lib/README.md) and [RSyntaxTextArea-LICENSE.txt](lib/RSyntaxTextArea-LICENSE.txt).
