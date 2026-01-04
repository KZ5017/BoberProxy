# **BoberProxy – Advanced Burp Suite Proxy Extension**

A powerful Burp Suite extension providing customizable request/response manipulation, cookie & CSRF management, redirect following, logging, filtering, and a fully programmable custom code execution engine — all through an integrated GUI tab.

---

## **Warning**

Based on experience, this extension affects the correct functioning of the built-in intercepting functionality. **It is recommended to deactivate this extension while using the burp proxy intercepting feature.**

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

It introduces a new tab inside Burp that includes:

* A full traffic logger
* Burp-native message viewers
* Request template editing
* Automated cookie & CSRF handling
* Redirect-chain following logic
* A programmable transformation pipeline
* A filtering/searching system
* Proxy mode with custom request generation

This extension works with both **Burp Proxy** traffic and **Burp Suite tools** (Repeater, Intruder, Scanner, etc.).

---

## **Features**

### ✔ Full request/response logging

* Displays host, method, URL, status code, body length, timestamps
* Auto-numbered rows
* Stores all entries, even filtered ones

### ✔ Advanced filtering system

Filter logs by:

* Host
* Method
* Path
* Response code
* Length (min, max, equals, not equals)
* Regex pattern search

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

Optionally follows up to *N* redirect responses (301, 302, 307, etc.)
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
* Jython standalone .jar (2.7.x)
* Python-like syntax compatible with Jython

### **Steps**

1. Download or clone this repository.
2. Open **Burp Suite → Extender → Options → Python Environment**.
3. Browse and select the **Jython standalone** JAR.
4. Go to **Extender → Extensions → Add**.
5. Choose:

   * **Extension type:** Python
   * **File:** `BoberProxy_final_v1.py`
6. The new **BoberProxy** tab should appear.

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
| `IContextMenuFactory`      | (Optional future expandability)       |
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
* Request Template Editor
* Template tooltip and helper controls

### Right Panel

* Full log table
* Filters button
* Search field
* Status bar
* Custom codeblock editor
* Cookie & CSRF settings
* Proxy mode toggle

---

## **Proxy Workflow**

When a proxied Request comes in:

1. **If it's a response:**

   * Update cookies
   * Update CSRF (regex-based)
   * Return

2. **If Proxy Mode is OFF:**
   → Forward request unchanged

3. **If Proxy Mode is ON:**
   The following steps occur:

#### 1. Extract original request data

Host, port, protocol, body, parameters.

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

A new HTTP request is built using Burp helpers.

#### 6. Send & optionally follow redirects

Redirect chain logic handles:

* `Location:` headers
* Relative/absolute URLs
* Cookies at each hop

#### 7. Return final request to Burp

Burp forwards it to the server.

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
* Must execute under a timeout (default 500 ms)
* Errors are displayed in the UI

This allows:

* Dynamic encryption/signing
* Payload wrapping
* Hashing
* CSRF-dependent request generation
* Parameter encoding

---

## **Cookie & CSRF Management**

### CookieManager

* Fully thread-safe
* Reads all `Set-Cookie:` headers
* Tracks additions/updates/deletions
* Injects cookies into outbound requests

### CsrfManager

* Extracts a CSRF token using user regex
* Stores a single token
* Allows manual override
* Integrates with templates

Default regex:

```
<input[^>]+name=["']csrfmiddlewaretoken["'][^>]*value=["']([^"']*)["']
```

---

## **Redirect Following**

The `follow_redirects_chain()` method:

1. Detects redirect via `Location:` header
2. Resolves relative or absolute URLs
3. Builds a minimal GET request
4. Maintains User-Agent where possible
5. Injects cookies (if enabled)
6. Updates CSRF token (if enabled)
7. Repeats up to *N* redirects

Uses Burp helpers:

* `buildHttpService`
* `makeHttpRequest`

---

## **Logging & Filtering**

### Logger features:

* Inserts new entries at the top
* Stores separate "displayed" vs "all" logs
* Rebuilds tables when filter changes
* Highlighting and search support
* Row renumbering

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
* Custom code execution restricted to safe Python subset
* Not compatible with Python3 syntax in Jython

---

## **License**

MIT License
Feel free to modify, extend, and redistribute.

---
