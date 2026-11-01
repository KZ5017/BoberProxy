<p align="center">
  <img width="767" height="512" alt="BoberProxy" src="https://github.com/user-attachments/assets/53abcb60-e218-4153-823f-d5c2a2f902d0" />
</p>

# **BoberProxy – Advanced Burp Suite Proxy Extension**

A Jython Burp Suite extension for template-based Proxy request workflows, cookie and CSRF management, redirect following, traffic logging, filtering, and custom payload transformations through an integrated GUI tab.

---

## **Warning**

BoberProxy preserves the interception action it receives from Burp when template
injection is disabled or the request does not match the payload parameters. Actively rewritten
requests still forward automatically. Disable **Injecting proxy from templates**
when you want to review the original matching requests manually.

---

## **Table of Contents**

1. [Overview](#overview)
2. [Features](#features)
3. [Installation](#installation)
4. [How It Works](#how-it-works)
5. [UI Components](#ui-components)
6. [Proxy Workflow](#proxy-workflow)
7. [Custom Codeblock](#custom-codeblock)
8. [Cookie & CSRF Management](#cookie--csrf-management)
9. [Redirect Following](#redirect-following)
10. [Logging & Filtering](#logging--filtering)
11. [Limitations](#limitations)
12. [License](#license)

---

## **Overview**

**BoberProxy** is a Burp Suite plugin (written in Jython-compatible Python) designed for power-users who need **full control over HTTP request transformation**, **automatic session/cookie/CSRF handling**, and **complex proxy-level workflows**.

The primary use case is routing command-line testing tools such as sqlmap, sstimap,
and ffuf through Burp, with custom transformations of selected payload parameter
values before the outgoing request is sent. Cookie and CSRF automation tracks
rotating session state during fuzzing. An optional CheckPage template retrieves
results from another known location and returns that response to the calling tool.

It introduces a new tab inside Burp that includes:

* A full traffic logger
* Burp-native message viewers
* Request template editing
* Automated cookie & CSRF handling
* Redirect-chain following logic
* A programmable transformation pipeline
* Capture filters and separate filters for stored log rows
* Proxy mode with custom request generation

The logger receives HTTP listener traffic from Burp tools, including Proxy and
Repeater. Template rewriting runs only in the Proxy listener; it does not rewrite
Repeater/Intruder requests merely because they appear in the log. Tool availability
depends on the Burp edition.

---

## **Features**

### ✔ Full request/response logging

* Displays host, method, URL, status code, body length, timestamps
* Auto-numbered rows
* Preserves accepted entries when display filters hide them
* Stores full accepted request/response content in an owned temporary archive

### ✔ Advanced filtering system

Filter logs by:

* Host
* Method
* Path
* Response code
* Length (min, max, equals, not equals)
* Java regex filtering of complete raw responses

### ✔ Built-in request/response viewers

Uses Burp’s own IMessageEditor components for maximum compatibility.

### ✔ Custom Codeblock execution engine

You can write Python code directly in the UI that dynamically transforms:

* Payload 1
* Payload 2
* CSRF token

Your code must return:

```python
return payload1, payload2, csrf_token
```

### ✔ Automatic Cookie Manager

Parses Set-Cookie headers, stores cookies, injects them into generated requests.

### ✔ Automatic CSRF token extraction

Uses a user-defined regex to automatically capture CSRF values from responses.

### ✔ Injecting proxy from templates

Intercepts Proxy requests and performs:

* Custom request building
* Cookie injection
* CSRF token injection
* Payload transformation
* Optional “Check Page” template processing

### ✔ Redirect following engine

Optionally follows up to ten redirect responses (301, 302, 303, 307, 308)
while updating cookies and CSRF tokens at every hop.

### ✔ Request Template Editor

Write custom request templates using markers such as:

```
p4yl04dm4rk3r
53c0undm4rk3r
c5rfm4rk3r
```

These placeholders are replaced during proxy request processing.

---

## **Installation**

### **Requirements**

* Burp Suite Professional or Community
* Jython standalone JAR; verified with **Jython 2.7.4**
* Python 2.7 syntax and libraries available in Burp's Jython runtime

The recorded integration environment is **Burp Suite Community 2026.10.1,
Jython 2.7.4, Java 26.0.2 on Windows**. Other Burp/Jython/Java versions have not
been verified by these results. The test tools under `tests/stabilization` are
development helpers; install the root extension for normal use.

### **Steps**

1. Download or clone this repository.
2. In Burp **Settings**, find **Extensions → Python environment**.
3. Browse and select the **Jython standalone** JAR.
4. Go to **Extensions → Installed → Add**.
5. Choose:

   * **Extension type:** Python
   * **File:** `BoberProxy.py` from the repository root
6. The new **BoberProxy** tab should appear. Check the extension's Output/Errors
   panes for the load result. On reload, remove the previous instance first so
   that only one main BoberProxy is installed. Older Burp layouts use an
   **Extender** section for these settings.

---

## **How It Works**

### High-level architecture

The extension implements several Burp interfaces:

| Interface                  | Purpose                               |
| -------------------------- | ------------------------------------- |
| `IBurpExtender`            | Initializes the extension             |
| `IHttpListener`            | Logs all Burp tool traffic            |
| `IProxyListener`           | Intercepts & transforms Proxy traffic |
| `ITab`                     | Creates the UI tab                    |
| `IExtensionStateListener`  | Closes owned work and UI on unload    |
| `IMessageEditorController` | Controls embedded message viewers     |

During initialization, BoberProxy:

1. Creates UI panels and split panes
2. Sets up message editors
3. Registers as an HTTP and Proxy listener
4. Initializes CookieManager and CsrfManager
5. Prepares the custom-code engine

---

## **UI Components**

### Left Panel

* Request and Response viewers (Burp-provided)
* Request Template and CheckPage Template editors, each with Load from Viewer/Clear
* Template tooltip and helper controls
* Proxy settings shortcut at the right end of the tab row
* Full log table below the viewers/templates, with the existing vertical divider
* Fixed single-row status strip below the log, visible independently of sidebar scrolling

### Right Panel

* Filters button
* Status/length/response-regex capture controls
* Custom codeblock editor
* Cookie & CSRF settings
* Proxy mode toggle

The control sidebar has a fixed width measured from its controls and font when
loaded. Resizing the Burp window changes the left workspace width. Logging,
workflow/session, custom code and output have independent layout groups; Test
and Reset share an equal-width row filling the available space. Short windows scroll the
sidebar vertically. Long code/regex lines scroll inside their own editors;
they do not widen the whole sidebar. Reload after changing the startup font/DPI
to measure a new width. Existing switches, defaults and processing behavior
are preserved.

The compact layout splits logging actions and session controls into shorter
rows, targeting about two-thirds of the former sidebar width while keeping
controls readable. CSRF and Response regex each have one visible text row and
their own horizontal scrollbar when the pattern exceeds the available width.
Injecting and Site map actions fill their rows. Logging, cookie/CSRF and
Test/Reset button pairs share each row equally. Request/response viewers start
at equal widths and share resizing space equally; their divider remains draggable.

The bottom status strip shows filter and recent-operation messages; long text is
available in tooltips. **Logging enabled** means capture is not paused, while
**Logging paused** means the Pause logging switch is active. These captions do
not indicate that a network request is running.

The **Proxy settings** shortcut opens Burp's existing native control. It reuses
the host button's gear icon and click behavior; availability depends on the
Burp UI. If the native control cannot be found, a status message directs you to
Proxy > Proxy settings.

The extension has no separate log search box, next-match navigator or row
highlighting function. Use **Filter → ResponseContent** to search stored
responses with regexes; Burp's own message editor search is a separate feature.

**Add selected to Site map** exports the selected original messages and also
includes their URLs in **Burp target scope**. Sorting and display filtering do
not change which selected messages are exported. The button tooltip states
the scope side effect.

---

## **Proxy Workflow**

The switch is named **Injecting proxy from templates**. Disabled or unmatched
requests retain their existing Burp interception action. Matching requests use
a settings snapshot captured at workflow start, including template bytes,
custom code, switches and regex. Editing controls affects subsequent workflows.

#### 1. Extract original request data

The two payload-name fields default to `q` and `w`. Values are extracted from
the query first, then an `application/x-www-form-urlencoded` body. Percent
escapes and `+` remain raw: `%252F+%2B` is not URL-decoded. The first nonempty
value for each slot wins; if both names are the same, the first slot is filled
before the second. A request with no nonempty selected payload is unmatched.
JSON/multipart values are not additional payload sources.

#### 2. Load request template

The template may contain markers:

* `p4yl04dm4rk3r` → main payload
* `53c0undm4rk3r` → secondary payload
* `c5rfm4rk3r` → CSRF token

#### 3. Run Custom Codeblock

If enabled, the code transforms:

* payload1
* payload2
* csrf_token

#### 4. Inject cookies

If auto-cookie is enabled.

#### 5. Rewrite request

A complete request is built from the Request Template using Burp helpers.
Markers are replaced once in the original template; inserted payload/token
text is not interpreted as another marker. Payloads are not automatically
URL-encoded. Request Template and CheckPage use the original Proxy service:
changing only the template Host header does not select a new network target.

#### 6. Send & optionally follow redirects

With **Use CheckPageTemplate OFF**, the generated Request Template is returned
to Burp for its single normal Proxy send. There is no additional internal RT
send and AutoFollow is disabled.

With **Use CheckPageTemplate ON**, the extension sends the Request Template
internally once, updates enabled cookie/token state and optionally follows
redirects. It then builds CheckPage using the original payloads and the updated
token. When custom code is enabled it runs again for CheckPage, including its
top-level code and side effects. Redirect policy is described below.

#### 7. Return final request to Burp

Burp forwards either the generated Request Template or the final CheckPage,
according to the mode above. A failure before any internal send falls back to
the original request with a diagnostic. A failure after an attempted internal
send drops the original instead of retrying a possibly accepted operation.
Burp's extension-drop error page can itself have HTTP status 200; read the
diagnostic/body rather than treating that status as workflow success.

---

## **Custom Codeblock**

Example default template:

```python
def custom_codeblock(payload1, payload2, csrf_token):
    """
    Custom transform hook that MUST accept and return exactly three values.
    """
    # default passthrough
    return payload1, payload2, csrf_token
```

### Rules:

* Must define a `custom_codeblock` function
* Must return exactly **three values**
* Each call has a configurable 1–30000 ms result deadline (default 500 ms)
* Errors are displayed in the UI

Return a tuple/list of three byte or text values. `None` means an empty payload;
for the CSRF token it means no token, so its template marker remains. Text uses
byte-valued code points 0–255, matching Burp's byte/string conversion. For other
Unicode characters, return explicitly encoded bytes, such as
`u'\u20ac'.encode('utf-8')`. Numbers, booleans and arbitrary objects are rejected
with a visible transformation error. Inserted payloads and token values are never
scanned again for template markers.

The deadline includes queue wait, compilation, top-level code, the function call
and output validation. One worker executes custom code and at most one job can
wait. `CUSTOM_BUSY` means capacity is occupied; `CUSTOM_TIMEOUT` means the result
deadline expired. Invalid timeout input shows `CUSTOM_CONFIG_ERROR`.

**Test** uses the same executor asynchronously. Changing its settings or
unloading the extension discards an outdated result. An RT/CheckPage workflow
uses the custom code/enabled/timeout snapshot captured at its start; each step
still executes the top-level code and function independently with that step's token.

An expired deadline does not forcibly stop Python/Java code or undo its external
side effects. A stuck worker can continue using CPU and blocks further custom
execution, including replacement workers after reload. Burp restart may be
needed. Custom code runs with Burp's Jython/Java permissions; this is not a sandbox.

This allows:

* Dynamic encryption/signing
* Payload wrapping
* Hashing
* CSRF-dependent request generation
* Parameter encoding

---

## **Cookie & CSRF Management**

### CookieManager

* Uses locked operations and coordinated workflow-local cookie/token state
* Reads all `Set-Cookie:` headers
* Tracks additions/updates/deletions
* Injects cookies into outbound requests

The compatibility mode uses one global jar and one CSRF token. Domain, Path and
Secure do not restrict injection: values collected from one target can reach
another target's generated request. Enabled automatics collect Proxy responses
and internal Request Template/redirect responses. An automation switch controls
both response updates and injection for that data.

Managed workflows are serialized through the final Proxy response. Each keeps
its own state for Request Template → redirects → CheckPage; unrelated passive
responses cannot replace that workflow's local token between steps. Clear
Cookies or Clear CSRF starts a new shared generation, invalidating old workflow
publication while clearing only the selected kind of data. This cannot undo a
request already handed to Burp, or coordinate server-side token changes caused
by clients outside the extension. A missing final response can retain ownership
until response/Clear/unload; this is not a guaranteed network cancellation.

`Max-Age` takes precedence over `Expires`; nonpositive Max-Age and past expiry
delete a cookie. Invalid expiry attributes are ignored. Empty values and the
literal `deleted` are valid cookie values. A deleted/expired cookie also
suppresses the old value in a template. A new valid Set-Cookie restores it;
**Clear Cookies** clears the jar and deletion markers, allowing the template's
own values again. Unmanaged template cookies are preserved.

### CsrfManager

* Extracts a CSRF token using user regex
* Stores a single token
* Offers Show CSRF and Clear CSRF; there is no manual token-entry control
* Integrates with templates

The regex is validated and compiled when edited. Its first capturing group is
the token; invalid patterns and patterns without a capture show a distinct
configuration error. A response without a matching token retains the previous
one. An empty captured string is a present, empty token; **Clear CSRF** makes
the token absent. Searches preserve raw response byte values and do not
implicitly decompress or apply a character encoding.

Default regex:

```
<input[^>]+name=["']csrfmiddlewaretoken["'][^>]*value=["']([^"']*)["']
```

---

## **Redirect Following**

The `_follow_redirects_chain()` path:

1. Detects redirect via `Location:` header
2. Resolves relative or absolute URLs
3. Builds a minimal GET request
4. Maintains User-Agent where possible
5. Injects cookies (if enabled)
6. Updates CSRF token (if enabled)
7. Repeats up to ten redirects

Uses Burp helpers:

* `buildHttpService`
* `makeHttpRequest`

Following requires **AutoFollow redirect on RT** to be selected. The ten-hop
limit, redirect loops and invalid destinations produce explicit workflow errors.
Redirects use the existing minimal GET policy, including after 307/308: Host,
Connection, User-Agent and enabled managed cookies; the original body and
Authorization header are not copied. Relative URLs use the actual service and
request path/query, and the last received response updates cookies/CSRF once.
Request Template and CheckPage keep the original proxy service even if their
Host header differs; redirect requests use the service selected by Location.

A shared 30-second scheduling budget covers template preparation, internal RT
and redirect calls, and CheckPage preparation. It cannot interrupt a blocking
Burp call; after that call returns, an expired budget prevents further steps.
The final proxied CheckPage exchange uses Burp's own network timeout. Failures
after an internal send drop the original request instead of resending it.

---

## **Logging & Filtering**

### Logger features:

* Appends stored metadata and displays newest rows first
* Keeps a stored set and a separately filtered display
* Rebuilds display matches in the background when filters change
* Keeps stable row IDs; deletion does not renumber remaining rows
* Supports multiple selection, sorting, Clear selected, Clear log and Pause logging

The main-panel **1xx–5xx**, **Size filter** and **Response regex** controls decide
which new responses are admitted. **Total size** measures the complete response
in bytes; **Body size** measures its body. The log columns use the same names.
**Minimum**, **Maximum** and **Not equal** provide the threshold and exclusion-list comparisons. A
Response regex uses Java `Pattern.find()` with default flags.

The **Filter** dialog affects already accepted rows without deleting their
stored messages. Host/Method/Status use exact text, Path uses a substring,
Body size uses integer equality/exclusion and ResponseContent searches complete
raw response headers and body using case-insensitive, DOTALL Java regexes.
Active fields combine with AND; an `eq` field accepts any listed value and
`not eq` rejects listed matches. An active empty field rejects rows. Body size
zero is a real value; unknown length remains blank.

Enter **one regex per line** in ResponseContent. Commas inside `a{1,3}` or `a,b`
belong to the pattern. Other dialog fields use comma-separated lists. Invalid
regexes/numbers show a validation error and retain the last valid filter.
Responses are not implicitly decompressed or charset-decoded for searching.

Complete accepted content is stored in a per-instance temporary archive;
in-memory records primarily contain metadata. Viewer/template/Site map reads
and regex searches run in bounded background work. Rapid selection changes
discard outdated viewer results. Clear/unload retire owned content and release
references; filesystem cleanup is asynchronous and can wait on an active read.
This archive is for the live extension session, not crash recovery or a saved
Burp project. Extension log clearing does not erase Burp's own HTTP history.

There is a shared **32 MiB budget for owned pending/active raw log snapshots**
and finite work queues. Queue/byte saturation or an archive write error visibly
pauses new admission, retaining accepted entries. Pending accepted work can
finish after Pause; resuming uses the Pause logging control. Read/export errors
are shown separately. The budget is not a bound on total JVM/process memory:
metadata grows with row count, and viewer/native-editor buffers and conversion
temporaries need additional memory. Full long-run load validation is K11 work.

### Filters include:

* Methods
* Status
* Path substring
* Regex pattern
* Body length conditions
* Combined logical filtering

---

## **Limitations**

* Requires Jython; CPython-only features cannot be used
* Some UI components depend on Burp versions
* Custom code is not sandboxed and has no guaranteed forced termination
* Not compatible with Python3 syntax in Jython
* Cookie/token storage is global, without Domain/Path/Secure isolation
* Java regexes have bounded execution capacity, but no guaranteed forced stop;
  an expensive pattern can occupy the worker until it finishes or Burp restarts
* Full HTTP/2 behavior and additional runtime versions are not verified by the
  recorded HTTP/1.x fixture checks; existing framing normalization is retained

---

## **License**

MIT License
Feel free to modify, extend, and redistribute.

---

## **Project Notes**

- [AGENTS.md](AGENTS.md)
- [AI_NOTES.md](AI_NOTES.md)
- [CHANGELOG.md](CHANGELOG.md)
