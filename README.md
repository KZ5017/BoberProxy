### Overview

BoberProxy is a Burp Suite extension written in Jython that provides a compact logging UI, request templating and forwarding, a local HTTP listener mode, cookie and CSRF token management, and a user-extensible payload transform hook. It’s designed for flexible, template-driven request replay and payload transformation while integrating with Burp’s request/response helpers and Site map features.

---

### Key capabilities

- **Logging panel** with sortable, filterable table of recorded HTTP responses and requests.
- **Request Template and CheckPage Template editors** that let you craft arbitrary raw HTTP requests and send them with marker-based substitution.
- **Local-server mode** that listens on 127.0.0.1:8081 and accepts raw HTTP requests, processing them through the same template/forwarding pipeline.
- **Follow-redirects direct-forward path** to forward an incoming request directly to a manually-configured host/port using Burp callbacks, bypassing template substitution when no payload markers are present.
- **CookieManager** that parses Set-Cookie headers and injects cookies into outgoing templated requests.
- **CsrfManager** that extracts token values from responses using a default or user-supplied regex and caches them for later injection.
- **Custom codeblock hook** — user-supplied Python function runs in a sandboxed thread with a timeout and must return exactly three values: (payload1, payload2, csrf_token). This allows dynamic payload transformation before template injection.
- **UI controls** for selective logging (status groups, size comparators, response regex), pausing, clearing, and adding selected entries to Burp’s Site map and scope.

---

### UI walkthrough

- Tabs on the left:
    - **Viewer**: split request/response message viewers using Burp IMessageEditor.
    - **Request Template**: editable message template used to build the outbound request. Use markers to place payloads and CSRF tokens.
    - **CheckPage Template**: optional follow-up request template used to replace original responses with a second request’s response.
- Right panel controls:
    - **Mode selector**: switch between Proxy mode (normal operation) and Local-server mode (starts local HTTP listener).
    - **Logging options**: enable specific status code groups (1xx–5xx), set length-based filters, and require response content matching a Java regex.
    - **Follow redirects**: if enabled and incoming payloads are absent, the extension can forward the original request directly to a configured host/scheme/port using Burp’s makeHttpRequest.
    - **Cookie and CSRF controls**: enable auto-update, view/clear jar and tokens, and edit CSRF extraction regex.
    - **Custom payload transform**: enable custom code, set timeout, define parameter names for incoming payloads, test code, and reset to a template.
    - **Buttons**: Load template from selected request, Clear, Add selected to Site map, Pause logging, Open filter dialog.

---

### How templating and markers work

- Template markers:
    - p4yl04dm4rk3r → payload1
    - 53c0undm4rk3r → payload2
    - c5rfm4rk3r → CSRF token (injected only if auto-update CSRF is enabled and token cached)
- Flow:
    1. Local server or request handler extracts incoming payloads (query/body) into payload1/payload2.
    2. If follow-redirects is enabled and no payloads present, the tool may forward the original request directly to a UI-configured host using Burp and return the raw response (no templating).
    3. If a custom codeblock is enabled it receives (payload1, payload2, csrf) and must return (payload1, payload2, csrf). The returned values are used for marker substitution.
    4. Cookies and CSRF token injection happen after substitution if their auto-update flags are enabled.
    5. The extension builds a proper HTTP message (fixes Content-Length) and sends it via Burp callbacks, then returns the response bytes to the local client or displays them in the UI.
- CheckPage Template:
    - Optional follow-up request built from a second template. If enabled and provided, the extension sends the check request to the same target and may use the check response instead of the original response for downstream consumption and for cookie/CSRF updates.

---

### Custom codeblock details and safety

- User code must define: def custom_codeblock(payload1, payload2, csrf_token): return payload1, payload2, csrf_token
- Execution:
    - Runs in a separate thread with user-controlled timeout (default 500 ms).
    - The extension enforces exact 3-element return; otherwise it falls back to original payloads and reports an error.
- Use cases:
    - Dynamic payload encoding/decoding, combining multiple inputs, extracting additional tokens from the incoming request, or constructing different payload values based on logic.
- Recommendations:
    - Keep the function deterministic, fast, and exception-safe. Prefer pure transformations; avoid network calls inside the hook.
    - Use the Test button to validate behavior before enabling in live flow.

---

### Typical usage patterns

- Quick replay with substitution:
    1. Capture a request in Burp.
    2. Load it into Request Template.
    3. Put markers where payloads should be inserted.
    4. Send sample payloads via the local listener or let the custom hook generate payloads.
    5. Inspect responses in the Viewer tab or let CheckPageTemplate validate responses.
- Session-aware replay:
    - Enable Auto-update cookies and Auto-update CSRF. The extension will parse Set-Cookie headers and extract CSRF values into the CsrfManager using the provided regex.
- Proxyless direct-forward debugging:
    - Turn on Follow-redirects and set the Scheme, Host, and Port in the UI; the extension will forward incoming requests directly using Burp’s HTTP client and return the exact response, useful for reproducing behavior against a target host.
- Automated payload transformations:
    - Implement a short custom_codeblock to modify payloads, for example to apply encryption, HMAC, or change parameter structure before the templated request is sent.

---

### Important tips and caveats

- CSRF regex: the default pattern looks for hidden inputs with the configured name. If your app uses different markup, customize the regex in the CSRF text area and test extraction with CheckPageTemplate results.
- Use the Test button for custom code to avoid blocking real traffic with invalid hooks.
- Local-server mode opens 127.0.0.1:8081 by default. Ensure the port is available. The server uses a bounded semaphore to limit concurrent payload processing.
- The extension builds outgoing messages with Burp helpers where possible. If templates are malformed or missing required markers, the extension will return a small fallback HTTP response and log the condition.
- Security: user-supplied code runs inside the Jython interpreter used by Burp. Only enable custom code from trusted sources and avoid running untrusted scripts.
- Performance: enable auto-update features and custom code only when needed; cookie/CSRF parsing and check requests add network calls and CPU work.

---

### Example quick start

- Load extension into Burp (Jython).
- Capture a login page response, enable Auto-update CSRF, set CSRF param name to the hidden field name, and enable Auto-update cookies.
- Load the login request into Request Template, replace username/password with p4yl04dm4rk3r and 53c0undm4rk3r markers.
- Optionally write a tiny custom_codeblock to URL-encode or encrypt payloads.
- Use the local-server mode or send crafted requests through Burp to exercise templated replay and watch cookie/CSRF updates and CheckPage follow-up behavior.

---
