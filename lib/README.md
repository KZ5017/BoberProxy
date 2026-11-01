# Bundled code-editor dependency

Keep this directory next to `BoberProxy.py`. In Burp, load the Python file as
before; do not add this library JAR as a separate extension. BoberProxy loads it
locally, without downloading dependencies at runtime.

- Artifact: `com.fifesoft:rsyntaxtextarea:3.6.3`
- File: `rsyntaxtextarea-3.6.3.jar`
- Source: [Maven Central](https://repo.maven.apache.org/maven2/com/fifesoft/rsyntaxtextarea/3.6.3/rsyntaxtextarea-3.6.3.jar)
- SHA-256: `5d81946b70a97fa5ea6884295a7fdd2a703cc3b0ef944796c7c696b4395413f6`
- Maven SHA-1, checked when downloading: `7c0980adcca5bb7823dc291fa4ebb375885e26d1`
- License: BSD-3-Clause; the complete upstream license is in
  [RSyntaxTextArea-LICENSE.txt](RSyntaxTextArea-LICENSE.txt), also present inside
  the JAR as `META-INF/LICENSE`.
- Upstream release: [3.6.3](https://github.com/bobbylight/RSyntaxTextArea/releases/tag/3.6.3).

The main implementation remains Jython 2.7. This library provides editing
features only; it does not change the Python runtime or execute code while
typing. Code completion, external language servers and the RSTAUI add-on are
not included.

If the dependency cannot be loaded, BoberProxy keeps the basic editor and
reports the degraded editor state. Restore the full directory structure and
reload the extension to use the enhanced editor.
