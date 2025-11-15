# -*- coding: latin-1 -*-
# Extender.py — BoberProxy (updated: mode switch, local listener, tabs, template controls, custom codeblock)
from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IMessageEditorController
from javax import swing
from java.awt import GridBagLayout, GridBagConstraints, Insets, Font, FlowLayout
from javax.swing.table import DefaultTableModel
from java.util.regex import Pattern
import threading, time, os, socket, traceback
from javax.swing.table import TableRowSorter
from java.util import Comparator
from java.awt import Color
from javax.swing.text import DefaultHighlighter
from javax.swing.event import ChangeListener
import re
from javax.swing import SortOrder, RowSorter
from java.awt.event import MouseAdapter
from javax.swing import SwingUtilities
from java.awt import FlowLayout


class CsrfManager(object):
    """
    Simple CSRF token cache + extractor.
    Stores last seen token for a given param name.
    Thread-safe via lock.
    """
    def __init__(self):
        self.lock = threading.Lock()
        # mapping: param_name -> last_value
        self.tokens = {}
        # pattern override (set by UI before calling update)
        self.pattern_to_use = None
        self.token_name = None

    def _to_text(self, data):
        """
        Robust conversion of various response forms to a unicode string.
        Handles:
         - bytes / bytearray
         - iterable of ints (Java byte[] / Jython byte[] view)
         - string repr like "array('b', [72, 84, ...])"
         - fallback to str()
        """
        try:
            # already bytes-like
            if isinstance(data, (bytes, bytearray)):
                try:
                    return data.decode("latin-1", "replace")
                except:
                    return data.decode("utf-8", "replace")

            # If it's an actual iterable (Java byte[], list of ints, etc.) but not a str
            if hasattr(data, '__iter__') and not isinstance(data, str):
                try:
                    out = bytearray()
                    for b in data:
                        try:
                            iv = int(b)
                        except Exception:
                            try:
                                iv = ord(b)
                            except Exception:
                                iv = 0
                        if iv < 0:
                            iv = iv + 256
                        out.append(iv)
                    return bytes(out).decode("latin-1", "replace")
                except Exception:
                    # fallthrough to string handling
                    pass

            # otherwise, try to parse common textual reprs like: array('b', [72, 84, ...])
            s = str(data)

            # pattern: array('b', [72, 84, ...])
            try:
                import re
                m = re.match(r"^\s*array\('b'\s*,\s*\[([0-9,\s]+)\]\s*\)\s*$", s)
                if m:
                    nums = [int(x.strip()) for x in m.group(1).split(',') if x.strip()]
                    if nums:
                        return bytes(nums).decode("latin-1", "replace")
            except Exception:
                pass

            # fallback: if string contains bracketed numbers like [72, 84, ...], try that
            try:
                import re
                m2 = re.search(r"\[([0-9,\s]+)\]", s)
                if m2:
                    parts = [p.strip() for p in m2.group(1).split(',') if p.strip().isdigit()]
                    if parts:
                        nums = [int(p) for p in parts]
                        return bytes(nums).decode("latin-1", "replace")
            except Exception:
                pass

            # final fallback: return the string representation
            return s

        except Exception:
            try:
                return str(data)
            except:
                return ""

    def update_from_response(self, response_bytes, param_name):
        """
        Extract token using either a user-supplied regex (pattern_to_use) or the default pattern.
        Returns (True, value) if found, else (False, None).
        """
        txt = self._to_text(response_bytes)
        if not txt:
            return False, None

        import re
        # prepare pattern: use UI override if set, else use default with param_name inserted
        pat_text = None
        try:
            if self.pattern_to_use:
                pat_text = str(self.pattern_to_use)
                # if pattern contains %s, substitute the param name (useful if user left %s)
                if "%s" in pat_text:
                    pat_text = pat_text % re.escape(param_name)
            else:
                pat_text = self._default_pattern_for(param_name)
        except Exception:
            pat_text = self._default_pattern_for(param_name)

        try:
            m = re.search(pat_text, txt, flags=re.IGNORECASE | re.DOTALL)
            if m:
                token = m.group(1)
                with self.lock:
                    self.tokens[param_name] = token
                return True, token
        except Exception:
            # invalid regex or matching error: ignore, return not found
            return False, None

        return False, None

    def _default_pattern_for(self, param_name):
        import re
        # default: look for input with name="param_name" and capture value attr
        return r'<input[^\>]+name=[\"\\\']' + re.escape(param_name) + r'["\\\'][^\>]*value=[\"\\\']([^\"\\\']*)["\\\']'

    def get_token(self, param_name):
        with self.lock:
            return self.tokens.get(param_name)
    
    def set_token(self, param_name, value):
        with self.lock:
            self.tokens[param_name] = value


    def clear(self, param_name=None):
        with self.lock:
            if param_name:
                if param_name in self.tokens:
                    del self.tokens[param_name]
            else:
                self.tokens = {}

    def dump(self):
        with self.lock:
            if not self.tokens:
                return "<no csrf tokens>"
            return "; ".join("%s=%s" % (k, v) for k, v in self.tokens.items())


class CookieManager(object):
    def __init__(self):
        self.jar = {}   # simple dict: {name: value}
        self.lock = threading.Lock()

    def _to_text(self, data):
        # helper: if bytes arrive, decode
        try:
            if isinstance(data, (bytes, bytearray)):
                try:
                    return data.decode("latin-1", "replace")
                except:
                    return data.decode("utf-8", "replace")
            else:
                return str(data)
        except:
            try:
                return str(data)
            except:
                return ""

    def update_from_response(self, response_bytes_or_text):
        """
        Parse Set-Cookie headers from response and update jar.
        Accepts response as bytes or str. Returns list of changes for logging.
        """
        txt = self._to_text(response_bytes_or_text)
        changes = []
        try:
            # split headers (we only need header area)
            hdr_part = txt.split("\r\n\r\n", 1)[0]
            for line in hdr_part.split("\r\n"):
                if not line:
                    continue
                line_lower = line.lower()
                if "set-cookie" in line_lower:
                    try:
                        val = line.split(":", 1)[1].strip()
                        # cookie-pair is before first ';'
                        pair = val.split(";", 1)[0].strip()
                        if "=" in pair:
                            name, v = pair.split("=", 1)
                            name = name.strip()
                            v = v.strip()
                            with self.lock:
                                old = self.jar.get(name)
                                if v == "" or v.lower().startswith("deleted"):
                                    # treat empty as deletion
                                    if name in self.jar:
                                        del self.jar[name]
                                        changes.append(("deleted", name, old, None))
                                else:
                                    self.jar[name] = v
                                    if old is None:
                                        changes.append(("added", name, None, v))
                                    else:
                                        changes.append(("updated", name, old, v))
                    except Exception:
                        # ignore malformed Set-Cookie
                        pass
        except Exception:
            pass
        return changes

    def inject_into_request(self, request_text):
        """
        Ensure the request_text (str) contains a Cookie: header merged from jar.
        If request has existing Cookie header, merge (jar overrides).
        Returns modified request_text (str).
        """
        try:
            txt = str(request_text)
        except:
            txt = request_text.encode("latin-1", "replace")

        # split header/body
        parts = txt.split("\r\n\r\n", 1)
        headers = parts[0].split("\r\n")
        body = parts[1] if len(parts) > 1 else ""

        # find existing Cookie header (if any), parse into dict
        existing = {}
        new_headers = []
        found_cookie = False
        for h in headers:
            if h.lower().startswith("cookie:"):
                found_cookie = True
                try:
                    cval = h.split(":",1)[1].strip()
                    for pair in cval.split(";"):
                        if "=" in pair:
                            n,v = pair.split("=",1)
                            existing[n.strip()] = v.strip()
                except:
                    pass
            else:
                new_headers.append(h)

        # merge: existing <- jar (jar overrides)
        with self.lock:
            merged = dict(existing)
            for k,v in self.jar.items():
                merged[k] = v

        # build Cookie header if merged not empty
        if merged:
            cookie_pairs = ["%s=%s" % (k, merged[k]) for k in merged]
            cookie_header = "Cookie: " + "; ".join(cookie_pairs)
            # insert cookie header near top (after request-line)
            # ensure new_headers has at least request-line as first element
            if len(new_headers) >= 1:
                # insert after request-line (index 1)
                # find Host header index to insert after it
                host_idx = None
                for idx, h in enumerate(new_headers):
                    if h.lower().startswith("host:"):
                        host_idx = idx
                        break
                if host_idx is not None:
                    new_headers.insert(host_idx + 1, cookie_header)
                else:
                    # fallback: put after request-line
                    new_headers.insert(1, cookie_header)

            else:
                new_headers.append(cookie_header)
        else:
            # nothing to add; keep headers without Cookie
            pass

        # reassemble
        new_txt = "\r\n".join(new_headers) + "\r\n\r\n" + body
        return new_txt

    def clear(self):
        with self.lock:
            self.jar = {}

    def dump(self):
        # return string representation for UI
        with self.lock:
            if not self.jar:
                return "<no cookies>"
            return "; ".join("%s=%s" % (k, v) for k, v in self.jar.items())



class SimpleMessageController(IMessageEditorController):
    def __init__(self):
        self._messageInfo = None
    def setMessageInfo(self, messageInfo):
        self._messageInfo = messageInfo
    def getHttpService(self):
        try:
            return self._messageInfo.getHttpService() if self._messageInfo else None
        except:
            return None
    def getRequest(self):
        try:
            return self._messageInfo.getRequest() if self._messageInfo else None
        except:
            return None
    def getResponse(self):
        try:
            return self._messageInfo.getResponse() if self._messageInfo else None
        except:
            return None

# MODULE-LEVEL helper: exec code in given namespace
def _exec_in_namespace(code, namespace):
    # run user code in the provided dict namespace
    exec(code, namespace)


# --- Filter dialog / UI ------------------------------------------
class FilterDialog(object):
    def __init__(self, parent):
        self.parent = parent
        from javax import swing
        from java.awt import GridBagLayout, GridBagConstraints, Insets
        self.dialog = swing.JDialog()
        self.dialog.setTitle("Display filter")
        # use simple JPanel as content
        p = swing.JPanel(GridBagLayout())
        c = GridBagConstraints()
        c.insets = Insets(4,4,4,4)
        c.fill = GridBagConstraints.HORIZONTAL
        row = 0
        # header
        c.gridx = 0; c.gridy = row; c.gridwidth = 3
        p.add(swing.JLabel("Select the options you want to filter by"), c)
        c.gridwidth = 1; row += 1

        # for each filter field create: checkbox, mode combo (eq/not eq), values field
        self.controls = {}
        # add new fields BodyLen and ResponseContent
        for fname in ["Host","Method","Path","Status","BodyLen","ResponseContent"]:
            cb = swing.JCheckBox("", False)
            mode = swing.JComboBox(["eq","not eq"])
            # for ResponseContent we want a single-line long text (regex); for BodyLen numeric list like others
            vals = swing.JTextField("", 40)
            c.gridx = 0; c.gridy = row; c.weightx = 0.0
            p.add(cb, c)
            c.gridx = 1; c.weightx = 0.0
            p.add(swing.JLabel(fname), c)
            c.gridx = 2; c.weightx = 0.0
            p.add(mode, c)
            c.gridx = 3; c.weightx = 1.0
            p.add(vals, c)
            self.controls[fname] = (cb, mode, vals)
            row += 1

        from java.awt import Dimension
        try:
            pref = p.getPreferredSize()
            p.setPreferredSize(Dimension(pref.width, max(pref.height, 300)))
        except:
            pass
        # majd setContentPane(p), pack(), stb.

        # set dialog content and sizing so components are visible
        try:
            self.dialog.setContentPane(p)
            self.dialog.pack()
            try:
                self.dialog.setModal(True)
            except:
                pass
            try:
                # position relative to parent component if available
                try:
                    self.dialog.setLocationRelativeTo(self.parent._component)
                except:
                    self.dialog.setLocationRelativeTo(None)
            except:
                pass
            # optional: set default close operation if available in Jython context
            try:
                self.dialog.setDefaultCloseOperation(swing.JDialog.DISPOSE_ON_CLOSE)
            except:
                pass
        except Exception:
            pass

        # buttons row: Apply / Reset / Cancel
        btnPanel = swing.JPanel(FlowLayout(FlowLayout.RIGHT, 6, 0))
        applyBtn = swing.JButton("Apply", actionPerformed=self._on_apply)
        resetBtn = swing.JButton("Reset", actionPerformed=self._on_reset)
        cancelBtn = swing.JButton("Cancel", actionPerformed=lambda e: self.dialog.dispose())
        btnPanel.add(applyBtn); btnPanel.add(resetBtn); btnPanel.add(cancelBtn)
        c.gridx = 0; c.gridy = row; c.gridwidth = 4; c.weightx = 1.0
        p.add(btnPanel, c)


    def load_from_parent(self):
        # populate controls with current parent display_filters
        try:
            for fname, (cb, mode, vals) in self.controls.items():
                cfg = self.parent.display_filters.get(fname, {"active": False, "mode": "eq", "values": []})
                try:
                    cb.setSelected(bool(cfg.get("active", False)))
                except:
                    pass
                try:
                    mode.setSelectedItem(str(cfg.get("mode","eq")))
                except:
                    pass
                try:
                    vals.setText(",".join(cfg.get("values",[])))
                except:
                    pass
        except:
            pass

    def _on_apply(self, evt=None):
        try:
            # build new config and set to parent
            for fname, (cb, mode, vals) in self.controls.items():
                active = bool(cb.isSelected())
                m = str(mode.getSelectedItem()) if mode.getSelectedItem() else "eq"
                vtxt = str(vals.getText() or "").strip()
                vals_list = [x.strip() for x in vtxt.split(",") if x.strip()]
                self.parent.display_filters[fname] = {"active": active, "mode": m, "values": vals_list}
            # close dialog
            self.dialog.dispose()
            # apply on parent UI thread
            try:
                swing.SwingUtilities.invokeLater(lambda: self.parent._refresh_table_display())
            except:
                self.parent._refresh_table_display()
        except Exception as e:
            try:
                self.parent.customStatusArea.setText("Filter apply error: %s" % e)
            except:
                pass
        
    def _on_reset(self, evt=None):
        """
        Reset all filter controls to inactive / empty and update parent.display_filters to defaults (inactive).
        """
        try:
            # Clear UI controls
            for fname, (cb, mode, vals) in self.controls.items():
                try:
                    cb.setSelected(False)
                except:
                    pass
                try:
                    mode.setSelectedItem("eq")
                except:
                    pass
                try:
                    vals.setText("")
                except:
                    pass

            # Reset parent's filter config to default inactive entries
            try:
                for fname in self.controls.keys():
                    self.parent.display_filters[fname] = {"active": False, "mode": "eq", "values": []}
            except:
                pass

            # Refresh parent display on UI thread
            try:
                swing.SwingUtilities.invokeLater(lambda: self.parent._refresh_table_display())
            except:
                try:
                    self.parent._refresh_table_display()
                except:
                    pass

        except Exception as e:
            try:
                self.parent.customStatusArea.setText("Filter reset error: %s" % e)
            except:
                pass



class LoggerUI(ITab):
    def __init__(self, callbacks, controller, msgEditor, callbacks_ref):
        # -------- core references / state ----------
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.controller = controller
        self.msgEditor = msgEditor
        self.callbacks_ref = callbacks_ref
        self._suspend_selection_events = False
        # __init__ végén
        self._init_display_filters()


        # search / highlight state
        self._search_matches = []
        self._current_match_idx = -1

        # local-server state
        self._local_server_thread = None
        self._local_server_running = False
        self._local_server_socket = None
        self._local_server_port = 8081
        self._mode = "proxy"  # "proxy" or "local"

        # other flags / storage
        self.paused = False
        self.running = False
        self.log_entries = []

        # Custom codeblock defaults
        self.custom_code_text = (
            "def custom_codeblock(payload1, payload2, csrf_token,):\n"
            "    \"\"\"\n"
            "    Custom transform hook that MUST accept and MUST return exactly three values.\n"
            "    Parameters\n"
            "    - payload1: first incoming payload (string)\n"
            "    - payload2: second incoming payload (string)\n"
            "    - csrf_token: csrf token (string)\n"
            "\n"
            "    MUST return exactly three elements in this order:\n"
            "    return payload1, payload2, csrf_token\n"
            "    \"\"\"\n"
            "    # Default behaviour: pass inputs through unchanged\n"
            "    return payload1, payload2, csrf_token\n"
        )

        self.custom_timeout_ms = 500
        self.payload_param_name = "q"

        # Cookie / CSRF managers + flags
        self.cookieManager = CookieManager()
        self.autoUpdateCookies = False

        self.csrfManager = CsrfManager()
        self.autoUpdateCsrf = False
        self.csrf_param_name = "csrfmiddlewaretoken"

        # default CSRF regex pattern (use %s for insertion of param name)
        self.csrf_default_pattern = r'<input[^\>]+name=[\"\\\']%s[\"\\\'][^\>]*value=[\"\\\']([^\"\\\']*)[\"\\\']'

        # -------- main split panes ----------
        self.mainSplit = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT)
        self.mainSplit.setDividerLocation(1280)

        # left split: detail (top) / table (bottom)
        self.leftSplit = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT)
        self.leftSplit.setDividerLocation(500)

        # ---------- BUILD LEFT SIDE (tabs) ----------
        # Viewer panel (Burp request/response message editors split)
        # Replace plain text detailArea with two IMessageEditor viewers (request / response)
        viewerPanel = swing.JPanel(GridBagLayout())
        vgc = GridBagConstraints()
        vgc.insets = Insets(0,0,0,0)
        vgc.fill = GridBagConstraints.BOTH
        vgc.weightx = 1.0
        vgc.weighty = 1.0

        # Create IMessageEditor instances (use controller that will be setMessageInfo on selection)
        # left: request editor (editable False), right: response editor (editable False)
        try:
            # prefer the msgEditor passed in (existing), but create separate viewers via callbacks if available
            self.reqViewer = callbacks.createMessageEditor(self.controller, False)
            self.respViewer = callbacks.createMessageEditor(self.controller, False)
            # obtain Swing components
            reqComp = self.reqViewer.getComponent()
            respComp = self.respViewer.getComponent()
        except Exception:
            # fallback: keep a plain text area if MessageEditor creation fails
            self.detailArea = swing.JTextArea()
            self.detailArea.setLineWrap(False)
            self.detailArea.setEditable(False)
            reqComp = swing.JScrollPane(self.detailArea)
            respComp = swing.JScrollPane(swing.JTextArea())

        # split pane: left=request, right=response (equal divider)
        self.viewerSplit = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT)
        self.viewerSplit.setLeftComponent(reqComp)
        self.viewerSplit.setRightComponent(respComp)
        # set a sensible initial divider location (half)
        self.viewerSplit.setDividerLocation(600)

        vgc.gridx = 0; vgc.gridy = 0; vgc.weighty = 1.0
        viewerPanel.add(self.viewerSplit, vgc)

        # Request Template panel
        reqTemplatePanel = swing.JPanel(GridBagLayout())
        rtc = GridBagConstraints()
        rtc.insets = Insets(2,2,2,2)
        rtc.fill = GridBagConstraints.BOTH
        rtc.weightx = 1.0
        rtc.weighty = 1.0

        # === Request Template: use Burp IMessageEditor (editable) ===
        # controller for template editors: simple controller that will provide no
        # associated IMessageInfo when editor is used stand-alone.
        self._template_req_controller = SimpleMessageController()
        try:
            self.reqTemplateEditor = callbacks.createMessageEditor(self._template_req_controller, True)
            self.reqTemplateComp = self.reqTemplateEditor.getComponent()
        except Exception:
            # fallback to plain text area if creation fails
            self.reqTemplateArea = swing.JTextArea()
            self.reqTemplateArea.setLineWrap(False)
            self.reqTemplateArea.setEditable(True)
            self.reqTemplateComp = swing.JScrollPane(self.reqTemplateArea)

        # small control row for request template (existing ctrlPanel kept)
        rtc.gridx = 0; rtc.gridy = 0; rtc.weighty = 1.0
        reqTemplatePanel.add(self.reqTemplateComp, rtc)

        # compact single-row control: buttons on the left, tooltip on the right (one line)
        rowPanel = swing.JPanel(GridBagLayout())
        rpc = GridBagConstraints()
        rpc.insets = Insets(2,2,2,2)
        rpc.fill = GridBagConstraints.HORIZONTAL
        rpc.gridy = 0

        # right: tooltip text field (non-editable) that expands to fill remaining width
        self.reqTooltipField = swing.JTextField("Markers: p4yl04dm4rk3r, 53c0undm4rk3r, c5rfm4rk3r ")
        self.reqTooltipField.setEditable(False)
        self.reqTooltipField.setFont(Font("Dialog", Font.PLAIN, 12))
        self.reqTooltipField.setBorder(None)
        try:
            # subtle background to look like a label (optional)
            self.reqTooltipField.setForeground(Color(220,220,220))
        except:
            pass

        # place btnPanel at gridx 0, weightx 0 (does not expand)
        rpc.gridx = 0
        rpc.weightx = 1.0    # tooltip stretches
        rpc.anchor = GridBagConstraints.WEST
        rowPanel.add(self.reqTooltipField, rpc)

        # left: buttons in a small flow panel
        btnPanel = swing.JPanel(FlowLayout(FlowLayout.RIGHT, 6, 0))
        self.loadFromViewerBtn = swing.JButton("Load from Viewer", actionPerformed=self._load_template_from_viewer)
        btnPanel.add(self.loadFromViewerBtn)
        self.clearReqTemplateBtn = swing.JButton("Clear", actionPerformed=self._clear_req_template)
        btnPanel.add(self.clearReqTemplateBtn)

        rpc.gridx = 1
        rpc.weightx = 0.0    # buttons do not expand
        rpc.anchor = GridBagConstraints.EAST
        rowPanel.add(btnPanel, rpc)

        # add the single-row panel into the template panel (same grid row as before)
        rtc.gridy = 1; rtc.weighty = 0.0; rtc.fill = GridBagConstraints.HORIZONTAL
        reqTemplatePanel.add(rowPanel, rtc)


        # === CheckPageTemplate: use Burp IMessageEditor (editable) ===
        self._template_check_controller = SimpleMessageController()
        try:
            self.checkPageEditor = callbacks.createMessageEditor(self._template_check_controller, True)
            self.checkPageComp = self.checkPageEditor.getComponent()
        except Exception:
            self.checkPageArea = swing.JTextArea()
            self.checkPageArea.setLineWrap(False)
            self.checkPageArea.setEditable(True)
            self.checkPageComp = swing.JScrollPane(self.checkPageArea)

        # CheckPageTemplate panel
        checkPagePanel = swing.JPanel(GridBagLayout())
        cpc = GridBagConstraints()
        cpc.insets = Insets(2,2,2,2)
        cpc.fill = GridBagConstraints.BOTH
        cpc.weightx = 1.0
        cpc.weighty = 1.0
        self.checkPageArea = swing.JTextArea()
        self.checkPageArea.setLineWrap(False)
        self.checkPageArea.setEditable(True)
        self.checkPageScroll = swing.JScrollPane(self.checkPageArea)
        cpc.gridx = 0; cpc.gridy = 0; cpc.weighty = 1.0
        checkPagePanel.add(self.checkPageComp, cpc)

        # compact single-row control for CheckPageTemplate: buttons on the left, tooltip on the right
        checkRowPanel = swing.JPanel(GridBagLayout())
        crpc = GridBagConstraints()
        crpc.insets = Insets(2,2,2,2)
        crpc.fill = GridBagConstraints.HORIZONTAL
        crpc.gridy = 0

        # right: tooltip text field (non-editable) that expands to fill remaining width
        self.checkTooltipField = swing.JTextField("Markers: p4yl04dm4rk3r, 53c0undm4rk3r, c5rfm4rk3r ")
        self.checkTooltipField.setEditable(False)
        self.checkTooltipField.setFont(Font("Dialog", Font.PLAIN, 12))
        self.checkTooltipField.setBorder(None)
        try:
            self.checkTooltipField.setForeground(Color(220,220,220))
        except:
            pass

        crpc.gridx = 0
        crpc.weightx = 1.0    # tooltip stretches
        crpc.anchor = GridBagConstraints.WEST
        checkRowPanel.add(self.checkTooltipField, crpc)

        # left: buttons in a small flow panel
        checkBtnPanel = swing.JPanel(FlowLayout(FlowLayout.RIGHT, 6, 0))
        self.loadToCheckBtn = swing.JButton("Load from Viewer", actionPerformed=self._load_check_from_viewer)
        checkBtnPanel.add(self.loadToCheckBtn)
        self.clearCheckTemplateBtn = swing.JButton("Clear", actionPerformed=self._clear_check_template)
        checkBtnPanel.add(self.clearCheckTemplateBtn)

        crpc.gridx = 1
        crpc.weightx = 0.0    # buttons do not expand
        checkRowPanel.add(checkBtnPanel, crpc)

        # add the single-row panel into the checkPage panel (reuse same grid row as before)
        cpc.gridy = 1; cpc.weighty = 0.0; cpc.fill = GridBagConstraints.HORIZONTAL
        checkPagePanel.add(checkRowPanel, cpc)


        # tabs on the left
        self.tabbed = swing.JTabbedPane()
        self.tabbed.addTab("Viewer", viewerPanel)
        self.tabbed.addTab("Request Template", reqTemplatePanel)
        self.tabbed.addTab("CheckPageTemplate", checkPagePanel)

        # Tab change handling: reset scroll/caret so user sees top
        class TabListener(ChangeListener):
            def __init__(self, parent):
                self.parent = parent
            def stateChanged(self, e):
                try:
                    sel = self.parent.tabbed.getSelectedIndex()
                    if sel == 1:
                        txt = self.parent.reqTemplateArea.getText()
                        if txt:
                            try:
                                self.parent.reqTemplateArea.setCaretPosition(0)
                                self.parent.reqTemplateScroll.getVerticalScrollBar().setValue(0)
                            except:
                                pass
                    elif sel == 2:
                        txt = self.parent.checkPageArea.getText()
                        if txt:
                            try:
                                self.parent.checkPageArea.setCaretPosition(0)
                                self.parent.checkPageScroll.getVerticalScrollBar().setValue(0)
                            except:
                                pass
                except:
                    pass

        self.tabbed.addChangeListener(TabListener(self))
        self.leftSplit.setLeftComponent(self.tabbed)

        # --- LOG table on left-bottom ---
        cols = ["#","Time","Host","Method","Path","Status","Len","BodyLen"]
        self.tableModel = DefaultTableModel([], cols)
        # Create main log table
        self.table = swing.JTable(self.tableModel)

        # sorter
        self.rowSorter = TableRowSorter(self.tableModel)
        self.table.setRowSorter(self.rowSorter)

        # -----------------------------
        # Table and row-sorting helpers
        # -----------------------------
        # (place this block right after self.table = swing.JTable(self.tableModel)
        #  and after you set up the rowSorter / auto-create flag)

        # ensure auto sorter is enabled (optional, but recommended)
        try:
            self.table.setAutoCreateRowSorter(True)
        except:
            pass

        # create & attach explicit row sorter if you use one
        try:
            self.rowSorter = TableRowSorter(self.tableModel)
            self.table.setRowSorter(self.rowSorter)
        except:
            # fallback: ignore if cannot create sorter
            pass

        # helper to reset sorting back to model order
        def reset_sorting_to_model_order():
            try:
                # If a sorter exists, clear its sort keys (this should reset visual sort)
                rs = self.table.getRowSorter()
                if rs is not None:
                    try:
                        rs.setSortKeys(None)
                        # refresh the view by re-setting the model (safe approach)
                        # we remove and reattach the sorter to force recalculation
                        self.table.setRowSorter(None)
                        self.table.setRowSorter(self.rowSorter)
                    except:
                        # best-effort fallback: remove sorter entirely (still a reset)
                        try:
                            self.table.setRowSorter(None)
                        except:
                            pass
                else:
                    # no sorter -> nothing to do
                    pass
            except Exception as e:
                # swallow errors but optionally log for debug
                try:
                    _log("reset_sorting_to_model_order failed: %s" % str(e))
                except:
                    pass

        # capture table reference for inner listener (avoid 'self' confusion)
        _table_ref = self.table

        # Add header mouse listener: clicking first column ("#") resets order.

        class HeaderClickListener(MouseAdapter):
            def mouseClicked(this, event):
                try:
                    # use captured table ref
                    col = _table_ref.columnAtPoint(event.getPoint())
                except Exception as e:
                    try:
                        _log("HeaderClickListener: cannot determine column: %s" % e)
                    except:
                        pass
                    return

                # if first column (index 0) clicked -> schedule reset after built-in sorter runs
                if col == 0:
                    def later():
                        try:
                            reset_sorting_to_model_order()
                            try:
                                _log("[DEBUG] Sorting reset to model order")
                            except:
                                pass
                        except Exception as e:
                            try:
                                _log("[DEBUG] Sorting reset error: %s" % e)
                            except:
                                pass
                    # ensure our reset runs after Swing's default sorter
                    try:
                        SwingUtilities.invokeLater(later)
                    except:
                        # final fallback: call immediately
                        try:
                            later()
                        except:
                            pass

        try:
            header = self.table.getTableHeader()
            header.addMouseListener(HeaderClickListener())
        except:
            pass


        self.table.setSelectionMode(swing.ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self.table.getSelectionModel().addListSelectionListener(self.on_table_select)
        self.leftSplit.setRightComponent(swing.JScrollPane(self.table))

        # attach left split to main split
        self.mainSplit.setLeftComponent(self.leftSplit)

        # ---------- RIGHT: controls (mode + filters + utility) ----------
        # We'll use a GridBagLayout for overall placement, but make groups use horizontal Box/Flow where needed
        from java.awt import Dimension
        rightWrapper = swing.JPanel()
        rightWrapper.setLayout(swing.BoxLayout(rightWrapper, swing.BoxLayout.Y_AXIS))        

        # Inner grid content (kept same as before)        
        rightContent = swing.JPanel(GridBagLayout())
        c = GridBagConstraints()
        c.insets = Insets(4,4,4,4)
        c.fill = GridBagConstraints.HORIZONTAL
        c.weightx = 0.5
        row = 0

        # Mode selector (proxy / local)
        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        modePanel = swing.JPanel()
        self.proxyModeBtn = swing.JToggleButton("Proxy mode", True, actionPerformed=lambda e: self._set_mode("proxy"))
        self.localModeBtn = swing.JToggleButton("Local-server", False, actionPerformed=lambda e: self._set_mode("local"))
        def _sync_mode_buttons():
            if self._mode == "proxy":
                self.proxyModeBtn.setSelected(True)
                self.localModeBtn.setSelected(False)
            else:
                self.proxyModeBtn.setSelected(False)
                self.localModeBtn.setSelected(True)
        modePanel.add(self.proxyModeBtn)
        modePanel.add(self.localModeBtn)
        rightContent.add(modePanel, c)
        row += 1

        # mode status label
        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        self.modeStatusLabel = swing.JLabel("Mode: proxy")
        rightContent.add(self.modeStatusLabel, c)
        row += 1
        c.gridwidth = 1

        # Logging header
        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        rightContent.add(swing.JLabel("Logging options"), c)
        row += 1
        c.gridwidth = 1

        # Status checks label + checkboxes on same row (compact)
        c.gridy = row; c.gridx = 0; c.gridwidth = 1
        c.weightx = 1.0
        c.anchor = GridBagConstraints.WEST
        rightContent.add(swing.JLabel("Status groups:"), c)

        # Use FlowLayout for the checkbox row (keeps them in one line and allows wrapping when needed)
        try:
            statusPanel = swing.JPanel(FlowLayout(FlowLayout.LEFT, 5, 0))
        except:
            statusPanel = swing.JPanel(FlowLayout(FlowLayout.LEFT, 5, 0))

        self.statusChecks = {}
        for label in ["1xx", "2xx", "3xx", "4xx", "5xx"]:
            cb = swing.JCheckBox(label, False)
            self.statusChecks[label] = cb
            statusPanel.add(cb)

        c.gridx = 1; c.gridwidth = 1
        c.weightx = 0.0
        c.anchor = GridBagConstraints.EAST
        rightContent.add(statusPanel, c)

        # restore defaults
        c.anchor = GridBagConstraints.CENTER
        c.weightx = 0.0
        row += 1

        # Len filter controls
        c.gridy = row; c.gridx = 0
        rightContent.add(swing.JLabel("Len filter:"), c)
        self.lenTypeCombo = swing.JComboBox(["Total len", "Response body len"])
        c.gridx = 1
        rightContent.add(self.lenTypeCombo, c)
        row += 1

        c.gridy = row; c.gridx = 0
        rightContent.add(swing.JLabel("Comparator:"), c)
        self.compCombo = swing.JComboBox(["Min Len", "Max Len", "Not eq Len"])
        c.gridx = 1
        rightContent.add(self.compCombo, c)
        row += 1

        c.gridy = row; c.gridx = 0
        rightContent.add(swing.JLabel("Value (bytes):"), c)
        self.sizeField = swing.JTextField("", 10)
        self.sizeField.setToolTipText("Enter one or more byte values, separated by commas (e.g. 100,200,512)")
        c.gridx = 1
        rightContent.add(self.sizeField, c)
        row += 1

        # Regex field
        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        rightContent.add(swing.JLabel("Response regex (Java):"), c)
        row += 1
        c.gridy = row
        self.regexField = swing.JTextField("", 20)
        rightContent.add(self.regexField, c)
        row += 1

        # Sitemap / Clear / Pause - horizontal button row (FlowLayout)
        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        c.weightx = 1.0
        c.anchor = GridBagConstraints.CENTER

        buttonPanel = swing.JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        # Add same set of buttons and keep names/actions
        self.addSitemapBtn = swing.JButton("Add selected to Site map", actionPerformed=self.add_selected_to_sitemap)
        buttonPanel.add(self.addSitemapBtn)

        self.clearBtn = swing.JButton("Clear log", actionPerformed=self.clear_log)
        buttonPanel.add(self.clearBtn)

        self.clearSelBtn = swing.JButton("Clear selected", actionPerformed=self.clear_selected)
        buttonPanel.add(self.clearSelBtn)

        self.pauseBtn = swing.JToggleButton("Pause logging", False, actionPerformed=self.toggle_pause)
        buttonPanel.add(self.pauseBtn)

        # Filter button: next to the Pause button (located on the right side)
        self.filterBtn = swing.JButton("Filter", actionPerformed=lambda e: self._open_filter_dialog())
        buttonPanel.add(self.filterBtn)


        # limit maximum expansion of the button row to avoid forcing horizontal scroll early
        buttonPanel.setMaximumSize(buttonPanel.getPreferredSize())
        rightContent.add(buttonPanel, c)

        # restore defaults
        c.gridwidth = 1
        c.weightx = 0.0
        row += 1

        # Follow-redirects and manual target controls (insert directly above the existing Use CheckPageTemplate row)

        # 1) Follow redirects checkbox
        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        self.followRedirectsChk = swing.JCheckBox("My tool wants to follow the redirects", False,
            actionPerformed=lambda e: self._on_toggle_follow_redirects())
        rightContent.add(self.followRedirectsChk, c)
        row += 1

        # 2) Scheme row: label + input (defaults to "http")
        c.gridy = row; c.gridx = 0; c.gridwidth = 1; c.weightx = 0.0; c.anchor = GridBagConstraints.WEST
        rightContent.add(swing.JLabel("Scheme(http/https):"), c)
        self.schemeField = swing.JTextField("http", 8)
        c.gridx = 1; c.weightx = 0.0; c.anchor = GridBagConstraints.EAST
        rightContent.add(self.schemeField, c)
        row += 1

        # 3) Host row: label + input (defaults to "bobr.pol")
        c.gridy = row; c.gridx = 0; c.gridwidth = 1; c.anchor = GridBagConstraints.WEST
        rightContent.add(swing.JLabel("Host(target host name):"), c)
        self.targetHostField = swing.JTextField("bobr.pol", 16)
        c.gridx = 1; c.anchor = GridBagConstraints.EAST
        rightContent.add(self.targetHostField, c)
        row += 1

        # 4) Port row: label + input (defaults to "80")
        c.gridy = row; c.gridx = 0; c.gridwidth = 1; c.anchor = GridBagConstraints.WEST
        rightContent.add(swing.JLabel("Port(1-65535):"), c)
        self.targetPortField = swing.JTextField("80", 8)
        c.gridx = 1; c.anchor = GridBagConstraints.EAST
        rightContent.add(self.targetPortField, c)
        row += 1

        # Initially disable the three input rows (they become enabled only when checkbox checked)
        try:
            for w in [self.schemeField, self.targetHostField, self.targetPortField]:
                w.setEnabled(False)
        except:
            pass

        # --- CheckPageTemplate usage toggle (UI) ---
        # Insert this *above* the existing Auto-update cookies checkbox block
        self.useCheckPageChk = swing.JCheckBox(
            "Use CheckPageTemplate", False,
            actionPerformed=lambda e: setattr(self, "useCheckPageTemplate", bool(self.useCheckPageChk.isSelected()))
        )
        # set the attribute default
        self.useCheckPageTemplate = False

        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        rightContent.add(self.useCheckPageChk, c)
        row += 1


        # Auto-update cookies checkbox
        self.autoUpdateChk = swing.JCheckBox(
            "Auto-update cookies from responses", False,
            actionPerformed=lambda e: setattr(self, "autoUpdateCookies", bool(self.autoUpdateChk.isSelected()))
        )
        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        rightContent.add(self.autoUpdateChk, c)
        row += 1

        # Cookies buttons in one compact horizontal panel
        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        c.weightx = 1.0
        c.anchor = GridBagConstraints.CENTER

        cookiePanel = swing.JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        self.clearCookiesBtn = swing.JButton("Clear Cookies", actionPerformed=lambda e: self._on_clear_cookies())
        cookiePanel.add(self.clearCookiesBtn)
        self.showCookiesBtn = swing.JButton("Show Cookies", actionPerformed=lambda e: self._on_show_cookies())
        cookiePanel.add(self.showCookiesBtn)
        cookiePanel.setMaximumSize(cookiePanel.getPreferredSize())
        rightContent.add(cookiePanel, c)

        # restore defaults
        c.gridwidth = 1
        c.weightx = 0.0
        row += 1

        # Auto-update CSRF checkbox
        self.autoUpdateCsrfChk = swing.JCheckBox(
            "Auto-update CSRF from responses", False,
            actionPerformed=lambda e: setattr(self, "autoUpdateCsrf", bool(self.autoUpdateCsrfChk.isSelected()))
        )
        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        rightContent.add(self.autoUpdateCsrfChk, c)
        row += 1

        # CSRF param name input
        c.gridy = row; c.gridx = 0; c.gridwidth = 1
        rightContent.add(swing.JLabel("Hidden param name:"), c)
        self.csrfParamField = swing.JTextField(self.csrf_param_name, 12)
        c.gridx = 1
        rightContent.add(self.csrfParamField, c)
        row += 1

        # CSRF Clear/Show in compact horizontal panel
        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        c.weightx = 1.0
        c.anchor = GridBagConstraints.CENTER

        csrfPanel = swing.JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        self.clearCsrfBtn = swing.JButton("Clear CSRF", actionPerformed=lambda e: self._on_clear_csrf())
        csrfPanel.add(self.clearCsrfBtn)
        self.showCsrfBtn = swing.JButton("Show CSRF", actionPerformed=lambda e: self._on_show_csrf())
        csrfPanel.add(self.showCsrfBtn)
        csrfPanel.setMaximumSize(csrfPanel.getPreferredSize())
        rightContent.add(csrfPanel, c)

        # restore defaults
        c.gridwidth = 1
        c.weightx = 0.0
        row += 1

        # CSRF regex label + reset button (kept in the same style as other rows)
        c.gridy = row; c.gridx = 0; c.gridwidth = 1
        rightContent.add(swing.JLabel("Regex pattern:"), c)
        self.resetCsrfRegexBtn = swing.JButton("Reset to default", actionPerformed=lambda e: self._on_reset_csrf_regex())
        c.gridx = 1
        rightContent.add(self.resetCsrfRegexBtn, c)
        row += 1

        # two-line text area for custom regex pattern
        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        self.csrfRegexArea = swing.JTextArea(self.csrf_default_pattern, 2, 40)
        self.csrfRegexArea.setLineWrap(False)
        self.csrfRegexArea.setToolTipText("Use %s to substitute the token name; default pattern shown")
        self.csrfRegexScroll = swing.JScrollPane(self.csrfRegexArea)
        rightContent.add(self.csrfRegexScroll, c)
        row += 1

        # ---------- Custom codeblock UI ----------
        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        rightContent.add(swing.JLabel("Custom payload transform"), c)
        row += 1
        c.gridwidth = 1

        self.useCustomChk = swing.JCheckBox("Use custom codeblock", False, actionPerformed=self._on_toggle_custom)
        c.gridy = row; c.gridx = 0
        rightContent.add(self.useCustomChk, c)
        self.timeoutField = swing.JTextField(str(self.custom_timeout_ms), 6)
        self.timeoutField.setToolTipText("Timeout (ms)")
        c.gridx = 1
        rightContent.add(self.timeoutField, c)
        row += 1

        c.gridy = row; c.gridx = 0
        rightContent.add(swing.JLabel("Payload param name(payload1 - required):"), c)
        self.payloadParamField = swing.JTextField(self.payload_param_name, 10)
        c.gridx = 1
        rightContent.add(self.payloadParamField, c)
        row += 1

        # new attribute default
        self.payload_param2_name = "w"

        # UI: second payload param name field (next to payloadParamField)
        c.gridy = row; c.gridx = 0
        rightContent.add(swing.JLabel("Payload param name(payload2 - optional):"), c)
        self.payloadParam2Field = swing.JTextField(self.payload_param2_name, 10)
        c.gridx = 1
        rightContent.add(self.payloadParam2Field, c)
        row += 1


        # custom code text area (multi-line)
        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        self.customCodeArea = swing.JTextArea(self.custom_code_text, 10, 40)
        self.customCodeArea.setLineWrap(False)
        self.customCodeScroll = swing.JScrollPane(self.customCodeArea)
        rightContent.add(self.customCodeScroll, c)
        row += 1

        # Buttons: Test | Reset (keep separated and with small gap)
        c.gridy = row
        c.gridwidth = 1
        c.gridx = 0
        self.testCodeBtn = swing.JButton("Test", actionPerformed=self._on_test_code)
        rightContent.add(self.testCodeBtn, c)

        c.gridx = 1
        self.resetBtn = swing.JButton("Reset", actionPerformed=self._reset_custom_code)
        rightContent.add(self.resetBtn, c)
        row += 1

        # Error/output area (fills remaining vertical space)
        # --- Error/output area (isolated in its own container, expands only within itself) ---
        from java.awt import Dimension, BorderLayout

        # Create a sub-panel with BorderLayout so the scroll pane fills it completely
        outputPanel = swing.JPanel(BorderLayout())

        # Create the output text area
        self.customStatusArea = swing.JTextArea()
        self.customStatusArea.setEditable(False)
        self.customStatusArea.setLineWrap(True)
        self.customStatusArea.setWrapStyleWord(True)
        self.customStatusArea.setFocusable(True)

        # Wrap text area in a scroll pane
        scroll = swing.JScrollPane(self.customStatusArea)
        scroll.setVerticalScrollBarPolicy(swing.JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        scroll.setHorizontalScrollBarPolicy(swing.JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        scroll.setPreferredSize(Dimension(0, 120))  # default visible area (~5 lines)

        # Add scroll pane to the output panel (fills the panel)
        outputPanel.add(scroll, BorderLayout.CENTER)

        # Layout constraints for the output panel itself
        c.gridy = row
        c.gridx = 0
        c.gridwidth = 2
        c.fill = GridBagConstraints.BOTH
        c.weightx = 1.0
        c.weighty = 1.0

        # Add the output panel instead of the scroll directly
        rightContent.add(outputPanel, c)
        row += 1


        # reset fill/grid hints
        c.fill = GridBagConstraints.HORIZONTAL
        c.gridwidth = 1
        c.weighty = 0.0

        # --- Fixed-height status label (prevents vertical layout shift) ---
        statusPanel = swing.JPanel(BorderLayout())
        self.customStatusLabel = swing.JLabel("")
        self.customStatusLabel.setPreferredSize(Dimension(0, 20))  # fixed height ~1 text line
        self.customStatusLabel.setHorizontalAlignment(swing.SwingConstants.LEFT)
        statusPanel.add(self.customStatusLabel, BorderLayout.CENTER)

        c.gridy = row
        c.gridx = 0
        c.gridwidth = 2
        c.fill = GridBagConstraints.HORIZONTAL
        c.weightx = 1.0
        c.weighty = 0.0
        rightContent.add(statusPanel, c)
        row += 1

        # initially disable custom controls (preserve original behavior)
        self._on_toggle_custom()

        # spacer at the end to push items to top
        c.gridy = row; c.weighty = 1.0
        rightContent.add(swing.JPanel(), c)
        row += 1

        # wrap rightContent into wrapper so layout can flexibly shrink
        rightWrapper.add(rightContent)

        # small rigid spacer below to prevent jitter when resizing
        rightWrapper.add(swing.Box.createRigidArea(Dimension(0, 5)))

        # scroll pane around the wrapper (not directly rightContent!)
        self.rightScroll = swing.JScrollPane(rightWrapper)
        
        # --- (Jython-kompatibilis) dynamic resize hookup for rightContent ---
        from java.awt import Dimension
        from java.awt.event import ComponentAdapter

        def _update_preferred_size(evt=None):
            try:
                viewport = self.rightScroll.getViewport()
                size = viewport.getExtentSize()
                if size.width > 0:
                    pref = rightContent.getPreferredSize()

                    # --- minimum width setting ---
                    MIN_WIDTH = 610   # below this value, do not shrink further (scrollbar comes)
                    new_w = max(MIN_WIDTH, size.width - 20)

                    # we only update if it really has changed
                    if pref.width != new_w:
                        rightContent.setPreferredSize(Dimension(new_w, pref.height))
                        rightContent.revalidate()
            except Exception:
                pass

        # ComponentAdapter descendant in Jython
        class _RightViewportListener(ComponentAdapter):
            def componentResized(self, e):
                _update_preferred_size(e)

        # add listener and one-time initializer call
        self.rightScroll.getViewport().addComponentListener(_RightViewportListener())
        _update_preferred_size()

        self.rightScroll.setHorizontalScrollBarPolicy(swing.JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        self.rightScroll.setVerticalScrollBarPolicy(swing.JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        self.rightScroll.getViewport().setScrollMode(swing.JViewport.SIMPLE_SCROLL_MODE)

        # attach to main split
        self.mainSplit.setRightComponent(self.rightScroll)

        # expose final component
        self._component = self.mainSplit

        # ensure mode buttons reflect initial state
        try:
            _sync_mode_buttons()
        except:
            pass


    def _on_toggle_follow_redirects(self, evt=None):
        try:
            enabled = bool(self.followRedirectsChk.isSelected())
        except:
            enabled = False
        try:
            for w in [self.schemeField, self.targetHostField, self.targetPortField]:
                try:
                    w.setEnabled(enabled)
                except:
                    pass
        except:
            pass

    def _open_filter_dialog(self, evt=None):
        try:
            # I assume that there is a FilterDialog class that expects the parent in its constructor.
            dlg = FilterDialog(self)
            # if the dialog has a load_from_parent method, call it
            try:
                dlg.load_from_parent()
            except Exception:
                # if there is no such method, it is not critical
                pass
            # position relative to the logger component
            try:
                dlg.dialog.setLocationRelativeTo(self._component)
            except Exception:
                try:
                    dlg.dialog.setLocationRelativeTo(None)
                except Exception:
                    pass
            dlg.dialog.setVisible(True)
        except Exception as e:
            # Let's try to update customStatusArea if it is available
            try:
                self.customStatusArea.setText("Cannot open filter dialog: %s" % e)
            except Exception:
                # completely silent fallback
                pass


    def _get_request_text_from_selected(self):
        try:
            view_sel = self.table.getSelectedRow()
            if view_sel < 0:
                return ""
            model_sel = self.table.convertRowIndexToModel(view_sel)
            # use self.displayed_entries if it exists
            if hasattr(self, "displayed_entries") and 0 <= model_sel < len(self.displayed_entries):
                entry = self.displayed_entries[model_sel]
            else:
                # fallback: full log_entries (security)
                entry = self.log_entries[model_sel]
            messageInfo = entry[0]
            try:
                reqb = messageInfo.getRequest()
                if reqb:
                    return self.helpers.bytesToString(reqb)
            except:
                return ""
        except:
            return ""
        return ""


    def _load_template_from_viewer(self, event=None):
        try:
            txt = self._get_request_text_from_selected()
            # set into editor (prefer setMessage)
            try:
                if hasattr(self, "reqTemplateEditor"):
                    # create bytes via helpers
                    b = None
                    try:
                        b = self.helpers.stringToBytes(txt)
                    except:
                        b = txt.encode("latin-1", "replace")
                    self.reqTemplateEditor.setMessage(b, True)
                else:
                    self.reqTemplateArea.setText(txt)
                try:
                    # try to reset caret/scroll for textarea fallback
                    if hasattr(self, "reqTemplateArea"):
                        self.reqTemplateArea.setCaretPosition(0)
                        self.reqTemplateScroll.getVerticalScrollBar().setValue(0)
                except:
                    pass
                self.set_status("Loaded request into Request Template")
                self.tabbed.setSelectedIndex(1)
            except Exception:
                # fallback: set as text
                try:
                    self.reqTemplateArea.setText(txt)
                except:
                    pass
        except:
            pass

    def _clear_req_template(self, event=None):
        try:
            if hasattr(self, "reqTemplateEditor"):
                try:
                    self.reqTemplateEditor.setMessage(None, True)
                except:
                    # fall back to setting empty bytes
                    try:
                        self.reqTemplateEditor.setMessage(self.helpers.stringToBytes(""), True)
                    except:
                        pass
            else:
                self.reqTemplateArea.setText("")
            try:
                if hasattr(self, "reqTemplateArea"):
                    self.reqTemplateArea.setCaretPosition(0)
                    self.reqTemplateScroll.getVerticalScrollBar().setValue(0)
            except:
                pass
            self.set_status("Request Template cleared")
        except:
            pass

    def _load_check_from_viewer(self, event=None):
        try:
            txt = self._get_request_text_from_selected()
            try:
                if hasattr(self, "checkPageEditor"):
                    b = None
                    try:
                        b = self.helpers.stringToBytes(txt)
                    except:
                        b = txt.encode("latin-1", "replace")
                    self.checkPageEditor.setMessage(b, True)
                else:
                    self.checkPageArea.setText(txt)
                try:
                    if hasattr(self, "checkPageArea"):
                        self.checkPageArea.setCaretPosition(0)
                        self.checkPageScroll.getVerticalScrollBar().setValue(0)
                except:
                    pass
                self.set_status("Loaded request into CheckPageTemplate")
                self.tabbed.setSelectedIndex(2)
            except Exception:
                try:
                    self.checkPageArea.setText(txt)
                except:
                    pass
        except:
            pass

    def _clear_check_template(self, event=None):
        try:
            if hasattr(self, "checkPageEditor"):
                try:
                    self.checkPageEditor.setMessage(None, True)
                except:
                    try:
                        self.checkPageEditor.setMessage(self.helpers.stringToBytes(""), True)
                    except:
                        pass
            else:
                self.checkPageArea.setText("")
            try:
                if hasattr(self, "checkPageArea"):
                    self.checkPageArea.setCaretPosition(0)
                    self.checkPageScroll.getVerticalScrollBar().setValue(0)
            except:
                pass
            self.set_status("CheckPageTemplate cleared")
        except:
            pass



    def _set_mode(self, mode):
        # toggle mode: "proxy" or "local"
        if mode == self._mode:
            return
        # stop local if switching away
        if mode == "proxy":
            # stop local server if running
            self._stop_local_server()
            self._mode = "proxy"
            self.modeStatusLabel.setText("Mode: proxy")
            self.proxyModeBtn.setSelected(True)
            self.localModeBtn.setSelected(False)
            # enable controls
            self._set_right_controls_enabled(True)
        else:
            # start local server
            ok = self._start_local_server()
            if ok:
                self._mode = "local"
                self.modeStatusLabel.setText("Mode: local (listening: 127.0.0.1:%d)" % self._local_server_port)
                self.proxyModeBtn.setSelected(False)
                self.localModeBtn.setSelected(True)
                # optionally disable some controls to avoid confusion
                self._set_right_controls_enabled(False)
            else:
                # failed to start -> keep proxy mode
                self._set_mode("proxy")

    def _set_right_controls_enabled(self, enabled):
        try:
            vp = self.rightScroll.getViewport().getView()
            for comp in vp.getComponents():
                pass
        except:
            pass
        for w in [self.sizeField, self.compCombo, self.lenTypeCombo, self.regexField,
                  self.addSitemapBtn, self.clearBtn, self.clearSelBtn, self.pauseBtn]:
            try:
                w.setEnabled(enabled)
            except:
                pass

    def _start_local_server(self):
        if self._local_server_running:
            return True
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", self._local_server_port))
            srv.listen(5)
        except Exception as e:
            swing.JOptionPane.showMessageDialog(None, "Failed to start local server on 127.0.0.1:%d: %s" % (self._local_server_port, e))
            return False

        self._local_server_socket = srv
        self._local_server_running = True

        def server_thread():
            try:
                while self._local_server_running:
                    try:
                        conn, addr = srv.accept()
                        
                        def handler(cn, ad):
                            """
                            Connection handler with bounded concurrency control.
                            We use a BoundedSemaphore stored on self to limit how many handlers
                            can run the heavy processing (self._handle_external_payload) at once.
                            This avoids unbounded CPU / memory growth while accepting connections quickly.
                            """
                            # ensure we have a semaphore on self (persistent across connections)
                            if not hasattr(self, "_fpl_req_semaphore"):
                                # tune this value to your environment (start with 60)
                                MAX_PARALLEL_WORKERS = 60
                                try:
                                    self._fpl_req_semaphore = threading.BoundedSemaphore(value=MAX_PARALLEL_WORKERS)
                                except Exception:
                                    # fallback, create a plain Semaphore if Bounded not available
                                    self._fpl_req_semaphore = threading.Semaphore(value=MAX_PARALLEL_WORKERS)

                            acquired = False
                            try:
                                # Acquire semaphore (blocks here if too many workers already running)
                                self._fpl_req_semaphore.acquire()
                                acquired = True

                                # ---- read request from socket (same behaviour as before) ----
                                cn.settimeout(3.0)
                                data = b""
                                try:
                                    chunk = cn.recv(65535)
                                    if chunk:
                                        data += chunk
                                except:
                                    # if recv fails, we'll fall back below
                                    pass

                                # prepare fallback response
                                fallback_body = b"BoberProxy local server OK\n"
                                fallback_resp = (
                                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
                                    + str(len(fallback_body)).encode("ascii")
                                    + b"\r\nConnection: close\r\n\r\n"
                                    + fallback_body
                                )

                                if not data:
                                    try:
                                        cn.sendall(fallback_resp)
                                    except:
                                        pass
                                    return

                                # ---- call existing payload handler (unchanged) ----
                                try:
                                    # keep original behaviour: handler returns raw response bytes
                                    resp = self._handle_external_payload(data)
                                    if resp:
                                        cn.sendall(resp)
                                    else:
                                        cn.sendall(fallback_resp)
                                except Exception as e:
                                    # minimal logging so we don't spam disk or break behaviour
                                    try:
                                        print("[FPL] handler exception:", e)
                                    except:
                                        pass
                                    try:
                                        cn.sendall(fallback_resp)
                                    except:
                                        pass

                            finally:
                                # ensure we always release (if we acquired)
                                if acquired:
                                    try:
                                        self._fpl_req_semaphore.release()
                                    except:
                                        pass
                                # close socket
                                try:
                                    cn.close()
                                except:
                                    pass


                        t = threading.Thread(target=handler, args=(conn, addr))
                        t.setDaemon(True)
                        t.start()
                    except Exception:
                        time.sleep(0.05)
            finally:
                try:
                    srv.close()
                except:
                    pass
                self._local_server_running = False

        thr = threading.Thread(target=server_thread)
        thr.setDaemon(True)
        thr.start()
        self._local_server_thread = thr
        return True

    def _stop_local_server(self):
        if not self._local_server_running:
            return
        self._local_server_running = False
        try:
            if self._local_server_socket:
                try:
                    self._local_server_socket.close()
                except:
                    pass
        except:
            pass
        self.modeStatusLabel.setText("Mode: proxy (local server stopped)")
        return

    def getTabCaption(self): return "BoberProxy"
    def getUiComponent(self): return self._component

    # helpers

    # --- Filter storage / apply helpers ---------------------------------
    # structure:
    # self.display_filters = {
    #   "Host": {"active": False, "mode": "eq"/"not eq", "values": ["a","b"]},
    #   "Method": {...},
    #   ...
    # }
    def _init_display_filters(self):
        # default fields (extended)
        try:
            self.display_filters = {
                "Host": {"active": False, "mode": "eq", "values": []},
                "Method": {"active": False, "mode": "eq", "values": []},
                "Path": {"active": False, "mode": "eq", "values": []},
                "Status": {"active": False, "mode": "eq", "values": []},
                "BodyLen": {"active": False, "mode": "eq", "values": []},            # new: numeric list
                "ResponseContent": {"active": False, "mode": "eq", "values": []},    # new: regex values
            }
        except:
            self.display_filters = {}


    def _row_matches_filters(self, entry):
        # entry is a tuple as stored in log_entries: (messageInfo, toolFlag, ts, isRequest, total_length, body_len)
        # map fields
        try:
            msg, tool, ts, isReq, total_length, body_len = entry
        except:
            return True
        # obtain values defensively
        try:
            analyzedReq = None
            method = ""
            host = ""
            path = ""
            status = ""
            try:
                analyzedReq = self.helpers.analyzeRequest(msg)
            except:
                analyzedReq = None
            if analyzedReq:
                try:
                    method = analyzedReq.getMethod()
                except:
                    method = ""
                try:
                    url = analyzedReq.getUrl()
                    if url:
                        host = url.getHost() or ""
                        q = url.getQuery()
                        path = (url.getPath() or "") + (("?" + q) if q else "")
                except:
                    pass
            # status only for responses
            try:
                resp = msg.getResponse()
                if resp:
                    try:
                        analyzedResp = self.helpers.analyzeResponse(resp)
                        try:
                            status = str(analyzedResp.getStatusCode() or "")
                        except:
                            status = ""
                    except:
                        status = ""
            except:
                status = ""
        except:
            method = host = path = status = ""

        field_map = {
            "Host": host or "",
            "Method": method or "",
            "Path": path or "",
            "Status": status or "",
        }

        # iterate active filters: all must pass (AND)
        try:
            for fname, cfg in self.display_filters.items():
                if not cfg.get("active"):
                    continue
                mode = cfg.get("mode", "eq")
                vals = cfg.get("values", [])
                cell = str(field_map.get(fname, "")).strip()
                if not vals:
                    return False

                matched = False

                # BodyLen: numeric comparisons (vals are CSV of ints or ranges — we'll treat as list of ints like earlier)
                if fname == "BodyLen":
                    try:
                        # body_len may be "" for requests or missing; treat as no-match
                        if body_len == "" or body_len is None:
                            matched = False
                        else:
                            actual_bl = int(body_len)
                            # try matching any provided numeric value
                            for v in vals:
                                try:
                                    vi = int(v)
                                    if vi == actual_bl:
                                        matched = True
                                        break
                                except:
                                    # ignore non-int entries
                                    pass
                    except:
                        matched = False

                # ResponseContent: vals are regex patterns; if any pattern matches the response text we consider matched
                elif fname == "ResponseContent":
                    try:
                        # build hay from response bytes if possible
                        resp_bytes = None
                        try:
                            resp_bytes = msg.getResponse()
                        except:
                            resp_bytes = None
                        hay = ""
                        try:
                            if resp_bytes:
                                hay = self.helpers.bytesToString(resp_bytes)
                            else:
                                # fallback to request text
                                req_bytes = msg.getRequest()
                                if req_bytes:
                                    hay = self.helpers.bytesToString(req_bytes)
                        except:
                            hay = ""
                        for v in vals:
                            v = v.strip()
                            if not v:
                                continue
                            try:
                                # use Java Pattern via imported Pattern earlier; compile per value
                                pat = Pattern.compile(v, Pattern.CASE_INSENSITIVE | Pattern.DOTALL)
                                m = pat.matcher(hay)
                                if m.find():
                                    matched = True
                                    break
                            except:
                                # if invalid Java regex, try Python re as fallback
                                try:
                                    if re.search(v, hay, flags=re.IGNORECASE|re.DOTALL):
                                        matched = True
                                        break
                                except:
                                    pass
                    except:
                        matched = False

                # Path partial-match behavior kept as before
                elif fname == "Path":
                    for v in vals:
                        v = str(v).strip()
                        if v and v in cell:
                            matched = True
                            break

                # Default: exact match against host/method/status
                else:
                    for v in vals:
                        v = str(v).strip()
                        if v and cell == v:
                            matched = True
                            break

                # apply mode
                if mode == "eq":
                    if not matched:
                        return False
                else:  # not eq
                    if matched:
                        return False

            return True
        except:
            return True

    def _refresh_table_display(self):
        try:
            col_count = self.tableModel.getColumnCount()
            column_names = [self.tableModel.getColumnName(c) for c in range(col_count)]
            new_rows = []
            # NEW: maintained list for visible (filtered) entries
            self.displayed_entries = []
            for entry in self.log_entries:
                if self._row_matches_filters(entry):
                    try:
                        messageInfo = entry[0]
                        ts = entry[2]
                        host = ""
                        method = ""
                        path = ""
                        status = ""
                        total_length = entry[4]
                        body_len = entry[5]
                        try:
                            analyzedReq = self.helpers.analyzeRequest(messageInfo)
                            method = analyzedReq.getMethod()
                            url = analyzedReq.getUrl()
                            if url:
                                host = url.getHost() or ""
                                q = url.getQuery()
                                path = (url.getPath() or "") + (("?" + q) if q else "")
                        except:
                            pass
                        try:
                            resp = messageInfo.getResponse()
                            if resp:
                                ar = self.helpers.analyzeResponse(resp)
                                try:
                                    status = ar.getStatusCode()
                                except:
                                    status = ""
                        except:
                            status = ""
                        row = ["", ts, host, method, path, status if status is not None else "", total_length if total_length is not None else "", body_len if body_len is not None else ""]
                        new_rows.append(row)
                        # KEY: stores the reference of the displayed entry
                        self.displayed_entries.append(entry)
                    except:
                        pass
            from javax.swing.table import DefaultTableModel
            new_model = DefaultTableModel(new_rows, column_names)
            self.table.setModel(new_model)
            self.tableModel = new_model
            try:
                self.rowSorter = TableRowSorter(self.tableModel)
                self.table.setRowSorter(self.rowSorter)
                self.table.setAutoCreateRowSorter(True)
            except:
                pass
            try:
                self._renumber_table()
            except:
                pass
        except Exception as e:
            try:
                self.customStatusArea.append("refresh_table_display error: %s\n" % e)
            except:
                pass



    # read template content from editor as python string (utf-8/latin-1 tolerant)
    def _editor_get_text(self, editor):
        try:
            # editor.getMessage() returns Java byte[] or None
            mb = editor.getMessage()
            if mb is None:
                return ""
            try:
                return self.helpers.bytesToString(mb)
            except:
                try:
                    return str(mb)
                except:
                    return ""
        except:
            # fallback: if we have a JTextArea fallback
            try:
                return getattr(self, "reqTemplateArea", swing.JTextArea()).getText()
            except:
                return ""

    # set template editor content from bytes/string
    def _editor_set_text(self, editor, text_or_bytes):
        try:
            if isinstance(text_or_bytes, (bytes, bytearray)):
                b = text_or_bytes
            else:
                try:
                    b = self.helpers.stringToBytes(str(text_or_bytes))
                except:
                    b = str(text_or_bytes).encode("latin-1", "replace")
            editor.setMessage(b, True)  # note: second arg 'isRequest' only affects highlighting in Burp editor
        except:
            try:
                # fallback for plain JTextArea
                if hasattr(self, "reqTemplateArea"):
                    self.reqTemplateArea.setText(str(text_or_bytes))
            except:
                pass


    def set_status(self, txt):
        try:
            self.statusLabel.setText(txt)
        except:
            pass

    def clear_log(self, evt=None):
        self.log_entries = []
        self.tableModel.setRowCount(0)
        try:
            self.lineNums.setText("")
        except:
            pass
        self.set_status("Log cleared")
        
    def clear_selected(self, evt=None):
        """
        Optimized deletion of selected rows from JTable + log_entries.
        Keeps data perfectly aligned and avoids Swing repaint per row.
        """
        try:
            sel_view_rows = list(self.table.getSelectedRows())
            if not sel_view_rows:
                swing.JOptionPane.showMessageDialog(None, "No rows selected.")
                return

            # Convert to model indices (ascending order)
            sel_model_indices = sorted(
                [self.table.convertRowIndexToModel(r) for r in sel_view_rows]
            )

            # Disable sorting and updates for speed
            sorter_was_enabled = self.table.getAutoCreateRowSorter()
            if sorter_was_enabled:
                self.table.setAutoCreateRowSorter(False)

            self.table.setEnabled(False)

            # --- Remove from log_entries efficiently ---
            delete_set = set(sel_model_indices)
            self.log_entries[:] = [
                entry for i, entry in enumerate(self.log_entries)
                if i not in delete_set
            ]
            # after: self.log_entries[:] = [ ... ] (this can remain)
            # DELETE from displayed_entries too, if any
            try:
                if hasattr(self, "displayed_entries"):
                    self.displayed_entries = [e for i,e in enumerate(self.displayed_entries) if i not in delete_set]
            except:
                pass

            # --- Build new table data from current tableModel ---
            row_count = self.tableModel.getRowCount()
            col_count = self.tableModel.getColumnCount()
            new_rows = []
            for i in range(row_count):
                if i not in delete_set:
                    new_rows.append([
                        self.tableModel.getValueAt(i, j)
                        for j in range(col_count)
                    ])

            # --- Replace the model in one step ---
            from javax.swing.table import DefaultTableModel
            column_names = [self.tableModel.getColumnName(c) for c in range(col_count)]
            new_model = DefaultTableModel(new_rows, column_names)
            self.table.setModel(new_model)
            self.tableModel = new_model

            # --- Restore sorting & renumber ---
            if sorter_was_enabled:
                self.rowSorter = swing.table.TableRowSorter(self.tableModel)
                self.table.setRowSorter(self.rowSorter)
                self.table.setAutoCreateRowSorter(True)

            try:
                self._renumber_table()
            except:
                pass

            # --- Cleanup ---
            self.table.setEnabled(True)
            try:
                self.detailArea.setText("")
            except:
                pass
            try:
                self.lineNums.setText("")
            except:
                pass

            self.set_status("Cleared %d selected" % len(sel_model_indices))

        except Exception as e:
            try:
                self.customStatusArea.append("clear_selected error: %s\n" % str(e))
            except:
                pass

    def toggle_pause(self, evt=None):
        self.paused = bool(self.pauseBtn.isSelected())
        self.set_status("Paused" if self.paused else "Running")

    # --------------------------------------------
    # Table sorting helpers (manual control)
    # --------------------------------------------
    def reset_sorting_to_model_order(self):
        """Reset JTable sorter to the model's natural order (disable sorting)."""
        try:
            sorter = self.table.getRowSorter()
            if sorter:
                sorter.setSortKeys(None)
        except Exception as e:
            try:
                self.customStatusArea.append("reset_sorting_to_model_order error: %s\n" % str(e))
            except:
                pass

    def sort_by_index_asc(self):
        """Sort JTable by '#' column (index ascending)."""
        try:
            from javax.swing import RowSorter, SortOrder
            sorter = self.table.getRowSorter()
            if sorter:
                sorter.setSortKeys([RowSorter.SortKey(0, SortOrder.ASCENDING)])
        except Exception as e:
            try:
                self.customStatusArea.append("sort_by_index_asc error: %s\n" % str(e))
            except:
                pass


    def add_selected_to_sitemap(self, event=None):
        view_sel = self.table.getSelectedRows()
        if not view_sel or len(view_sel) == 0:
            swing.JOptionPane.showMessageDialog(None, "No rows selected.")
            return
        model_sel = [self.table.convertRowIndexToModel(v) for v in view_sel]
        count = 0
        for r in model_sel:
            try:
                entry = self.log_entries[r]
                msg = entry[0]
                try:
                    self.callbacks_ref.addToSiteMap(msg)
                    try:
                        url = self.helpers.analyzeRequest(msg).getUrl()
                        if url:
                            self.callbacks_ref.includeInScope(url)
                    except:
                        pass
                    count += 1
                except Exception as e:
                    print("addToSiteMap error:", e)
            except Exception as e:
                print("mapping error:", e)
        self.set_status("Added %d selected to Site map" % count)
    

    def _on_clear_cookies(self, evt=None):
        try:
            self.cookieManager.clear()
            self.customStatusArea.setText("Cookies cleared.")
        except Exception as e:
            try:
                self.customStatusArea.setText("Error clearing cookies: %s" % e)
            except:
                pass

    def _on_show_cookies(self, evt=None):
        try:
            txt = self.cookieManager.dump()
            # put into customStatusArea so user sees current jar
            self.customStatusArea.setText("Current cookies:\n%s" % txt)
        except Exception as e:
            try:
                self.customStatusArea.setText("Error showing cookies: %s" % e)
            except:
                pass

    def _on_clear_csrf(self, evt=None):
        try:
            pname = str(self.csrfParamField.getText()).strip()
            if not pname:
                self.customStatusArea.setText("No param name specified.")
                return
            self.csrfManager.clear(pname)
            self.customStatusArea.setText("Cleared CSRF token for: %s" % pname)
        except Exception as e:
            try:
                self.customStatusArea.setText("Error clearing CSRF: %s" % e)
            except:
                pass

    def _on_show_csrf(self, evt=None):
        try:
            pname = str(self.csrfParamField.getText()).strip()
            if not pname:
                self.customStatusArea.setText("Hidden param name: (empty)\nAll tokens: %s" % self.csrfManager.dump())
                return
            val = self.csrfManager.get_token(pname)
            if val is None:
                self.customStatusArea.setText("No token cached for: %s" % pname)
            else:
                self.customStatusArea.setText("Cached %s = %s" % (pname, val))
        except Exception as e:
            try:
                self.customStatusArea.setText("Error showing CSRF: %s" % e)
            except:
                pass

    def _on_reset_csrf_regex(self, evt=None):
        try:
            self.csrfRegexArea.setText(self.csrf_default_pattern)
            try:
                self.customStatusArea.setText("CSRF regex reset to default.")
            except:
                pass
        except Exception as e:
            try:
                self.customStatusArea.setText("Error resetting CSRF regex: %s" % e)
            except:
                pass


    # selection -> show request/response és caret alapviselkedés
    def on_table_select(self, event):
        if getattr(self, "_suspend_selection_events", False):
            return

        view_sel = self.table.getSelectedRow()
        if view_sel < 0:
            # clear viewers
            try:
                if hasattr(self, "reqViewer"):
                    self.controller.setMessageInfo(None)
                    self.reqViewer.setMessage(None)
                    self.respViewer.setMessage(None)
            except:
                pass
            return
        try:
            model_sel = self.table.convertRowIndexToModel(view_sel)
            if hasattr(self, "displayed_entries") and 0 <= model_sel < len(self.displayed_entries):
                entry = self.displayed_entries[model_sel]
            else:
                entry = self.log_entries[model_sel]
            messageInfo = entry[0]
            # ... continue using messageInfo in the same way
            # set controller messageInfo so MessageEditor can query request/response via controller
            try:
                self.controller.setMessageInfo(messageInfo)
            except:
                pass

            # Update request viewer: show request bytes
            try:
                if hasattr(self, "reqViewer"):
                    # IMessageEditor.setMessage(messageBytes, isRequest) -> show relevant part
                    req_bytes = None
                    try:
                        req_bytes = messageInfo.getRequest()
                    except:
                        req_bytes = None
                    if req_bytes:
                        self.reqViewer.setMessage(req_bytes, True)
                    else:
                        self.reqViewer.setMessage(None, True)
            except:
                pass

            # Update response viewer: show response bytes
            try:
                if hasattr(self, "respViewer"):
                    resp_bytes = None
                    try:
                        resp_bytes = messageInfo.getResponse()
                    except:
                        resp_bytes = None
                    if resp_bytes:
                        self.respViewer.setMessage(resp_bytes, False)
                    else:
                        self.respViewer.setMessage(None, False)
            except:
                pass

            # try to reset any per-viewer caret/scroll if possible (best-effort)
            try:
                # if we fell back to text area, set caret
                if hasattr(self, "detailArea") and self.detailArea is not None:
                    self.detailArea.setCaretPosition(0)
            except:
                pass

            # keep search UI behavior: if user typed >=2 chars, we can still attempt to search in the response text
            try:
                text = str(self.searchField.getText()).strip()
            except:
                text = ""
            if len(text) >= 2:
                # best-effort: run previous do_search on the textual response if we can obtain it
                try:
                    hay = ""
                    if messageInfo.getResponse():
                        hay = self.helpers.bytesToString(messageInfo.getResponse())
                    elif messageInfo.getRequest():
                        hay = self.helpers.bytesToString(messageInfo.getRequest())
                    # replace detailArea content for search/highlight flow if detailArea exists
                    if hasattr(self, "detailArea") and self.detailArea is not None:
                        self.detailArea.setText(hay)
                        SwingUtilities.invokeLater(lambda: self.do_search(scroll_if_checked=True))
                except:
                    pass
            else:
                # nothing to search: nothing more to do
                pass

        except Exception as e:
            print("on_table_select error:", e)


    def should_log(self, toolFlag, messageIsRequest, messageInfo):
        if self.paused:
            return False
        mode = True
        if messageIsRequest:
            return False
        resp = messageInfo.getResponse()
        if resp is None:
            return False
        try:
            analyzed = self.helpers.analyzeResponse(resp)
            status = None
            try:
                status = analyzed.getStatusCode()
            except:
                status = None
        except:
            analyzed = None
            status = None
        any_checked = any(cb.isSelected() for cb in self.statusChecks.values())
        if any_checked:
            ok = False
            for label, cb in self.statusChecks.items():
                if not cb.isSelected(): continue
                try:
                    base = int(label[0])
                    if status is not None and status >= base*100 and status < (base+1)*100:
                        ok = True
                        break
                except:
                    pass
            if not ok:
                return False
        val_text = str(self.sizeField.getText()).strip()
        if val_text:
            blocked_values = []
            for part in val_text.split(","):
                part = part.strip()
                if not part:
                    continue
                try:
                    blocked_values.append(int(part))
                except:
                    pass
            if not blocked_values:
                return False
            len_type = str(self.lenTypeCombo.getSelectedItem())
            try:
                if len_type == "Total len":
                    actual = len(resp)
                else:
                    if analyzed is not None:
                        body_off = analyzed.getBodyOffset()
                        actual = len(resp) - body_off
                    else:
                        actual = len(resp)
            except:
                actual = len(resp)
            comp = str(self.compCombo.getSelectedItem())
            if comp == "Min Len":
                if actual < min(blocked_values):
                    return False
            elif comp == "Max Len":
                if actual > max(blocked_values):
                    return False
            elif comp == "Not eq Len":
                if actual in blocked_values:
                    return False

        pattern_text = str(self.regexField.getText()).strip()
        if pattern_text:
            try:
                pat = Pattern.compile(pattern_text)
                hay = self.helpers.bytesToString(resp) if resp else ""
                m = pat.matcher(hay)
                if not m.find():
                    return False
            except:
                return False
        return True

    # append_log_row (filter-aware)
    def append_log_row(self, toolFlag, host, method, path, status, total_length, messageInfo, isRequest):
        try:
            self._suspend_selection_events = True
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            body_len = ""
            try:
                if not isRequest and messageInfo.getResponse():
                    analyzedResp = self.helpers.analyzeResponse(messageInfo.getResponse())
                    bo = analyzedResp.getBodyOffset()
                    body_len = len(messageInfo.getResponse()) - bo
                else:
                    body_len = ""
            except:
                body_len = ""

            # 1) Always insert into full log storage (newest first)
            self.log_entries.insert(0, (messageInfo, toolFlag, ts, isRequest, total_length, body_len))

            # 2) Build the row as before (for potential table insertion)
            row = ["", ts, host, method, path,
                status if status is not None else "",
                total_length if total_length is not None else "",
                body_len if body_len is not None else ""]

            # 3) Decide whether to show it immediately based on display filters
            try:
                # if _row_matches_filters not defined or filters not initialized, assume match
                should_show = True
                if hasattr(self, "_row_matches_filters") and hasattr(self, "display_filters"):
                    # note: _row_matches_filters expects an entry tuple like in self.log_entries
                    should_show = self._row_matches_filters(self.log_entries[0])
            except:
                should_show = True

            # 4) Insert into table only if it should be displayed
            try:
                if should_show:
                    try:
                        self.tableModel.insertRow(0, row)
                    except Exception:
                        self.tableModel.addRow(row)
                    # after you put the row in the tableModel:
                    try:
                        # make sure self.display entries exist and insert them as the first elements of the table
                        if not hasattr(self, "displayed_entries"):
                            self.displayed_entries = []
                        # in the case of insertRow(0, row) the new element is placed at index 0 in the table -> we insert it into displayed_entries in the same way
                        self.displayed_entries.insert(0, self.log_entries[0])
                    except:
                        pass

                    # restore/refresh sorter model behavior if needed (keeps ui consistent)
                    try:
                        # if rowSorter exists, reattach to keep sorting functional
                        if getattr(self, "rowSorter", None) is not None:
                            # best-effort: ensure table model and sorter are synchronized
                            self.table.setRowSorter(None)
                            self.rowSorter = TableRowSorter(self.tableModel)
                            self.table.setRowSorter(self.rowSorter)
                            self.table.setAutoCreateRowSorter(True)
                    except:
                        pass
                    # renumber visible table
                    try:
                        self._renumber_table()
                    except:
                        pass
                else:
                    # If not shown, do nothing to the visible table (entry is in log_entries)
                    # Optionally: keep status or UI hint that entry was logged but filtered out
                    pass
            except Exception:
                # fallback: always insert to table if something goes wrong with filtering
                try:
                    self.tableModel.insertRow(0, row)
                except Exception:
                    try:
                        self.tableModel.addRow(row)
                    except:
                        pass
                try:
                    self._renumber_table()
                except:
                    pass

            # 5) Update status
            try:
                self.set_status("Logged: %s" % path)
            except:
                pass

        finally:
            self._suspend_selection_events = False


    def _renumber_table(self):
        try:
            rc = self.tableModel.getRowCount()
            for i in range(rc):
                self.tableModel.setValueAt(i+1, i, 0)
        except Exception as e:
            print("renumber error:", e)

    # ---------------------------
    # Custom codeblock helpers
    # ---------------------------
    def _on_toggle_custom(self, evt=None):
        enabled = bool(self.useCustomChk.isSelected())
        for w in [self.customCodeArea, self.payloadParamField, self.payloadParam2Field, self.testCodeBtn, self.resetBtn, self.timeoutField]:
            try:
                w.setEnabled(enabled)
            except:
                pass
        # show brief status
        try:
            if enabled:
                self.customStatusLabel.setText("Custom codeblock enabled")
            else:
                self.customStatusLabel.setText("")
        except:
            pass

    def _on_test_code(self, evt=None):
        # Force test values exactly as requested
        test_payload1 = "TestPayload1"
        test_payload2 = "TestPayload2"
        test_csrf = "TestCSRF_Token"

        try:
            t_ms = int(self.timeoutField.getText())
        except:
            t_ms = self.custom_timeout_ms

        ok, out, err = self.run_user_code(test_payload1, timeout_ms=t_ms, incoming_payload2=test_payload2, incoming_csrf=test_csrf)

        if ok:
            if isinstance(out, (list, tuple)) and len(out) == 3:
                try:
                    self.customStatusArea.setText("Test OK!\nOutput:\npayload1=%s\npayload2=%s\ncsrf_token=%s" % (out[0], out[1], out[2]))
                except:
                    pass
            else:
                try:
                    self.customStatusArea.setText("Test failed: user code did not return exactly 3 values.")
                except:
                    pass
        else:
            try:
                self.customStatusArea.setText("Error:\n%s" % str(err))
            except:
                pass


    def _reset_custom_code(self, event=None):
        # Reset the user code area to a simple backward-compatible template.
        # English comments inside code are required — keep them short.
        default_template = (
            "def custom_codeblock(payload1, payload2, csrf_token,):\n"
            "    \"\"\"\n"
            "    Custom transform hook that MUST accept and MUST return exactly three values.\n"
            "    Parameters\n"
            "    - payload1: first incoming payload (string)\n"
            "    - payload2: second incoming payload (string)\n"
            "    - csrf_token: csrf token (string)\n"
            "\n"
            "    MUST return exactly three elements in this order:\n"
            "    return payload1, payload2, csrf_token\n"
            "    \"\"\"\n"
            "    # Default behaviour: pass inputs through unchanged\n"
            "    return payload1, payload2, csrf_token\n"
        )


        try:
            self.customCodeArea.setText(default_template)
        except:
            pass



    def run_user_code(self, incoming_payload1, timeout_ms=500, incoming_payload2=None, incoming_csrf=None):
        """
        Execute user's custom_codeblock and enforce that the function:
        def custom_codeblock(payload1, payload2, csrf_token,)
        returns exactly three values in order: payload1, payload2, csrf_token

        Returns (ok, out_tuple_or_none, err_str)
        - ok: True on success
        - out_tuple_or_none: (payload1, payload2, csrf_token) tuple when ok True
        - err_str: error message when ok False
        """
        user_code_text = str(self.customCodeArea.getText())
        ns = {}
        try:
            _exec_in_namespace(user_code_text, ns)
        except Exception as e:
            import traceback as _tb
            return False, None, "Compilation error: %s\n%s" % (e, _tb.format_exc())

        if 'custom_codeblock' not in ns or not callable(ns.get('custom_codeblock')):
            return False, None, "custom_codeblock not defined as callable in user code"

        result = {'ok': False, 'out': None, 'exc': None}

        def _call_custom(ns, result, p1, p2, csrf):
            try:
                fn = ns.get('custom_codeblock')
                # Force calling with exactly 3 args
                out = fn(p1, p2, csrf)
                result['out'] = out
                result['ok'] = True
            except Exception as e:
                try:
                    import traceback as _tb
                    result['exc'] = str(e) + "\n" + _tb.format_exc()
                except:
                    result['exc'] = str(e)

        t = threading.Thread(target=_call_custom, args=(ns, result, incoming_payload1, incoming_payload2, incoming_csrf))
        t.setDaemon(True)
        t.start()
        t.join(float(timeout_ms) / 1000.0)

        if t.isAlive():
            return False, None, "timeout"

        if not result['ok']:
            return False, None, result.get('exc', 'Unknown error')

        out_obj = result['out']

        # Enforce that out_obj is a sequence/tuple/list of exactly 3 elements
        if not isinstance(out_obj, (list, tuple)):
            return False, None, "custom_codeblock must return a tuple/list of 3 elements: (payload1, payload2, csrf_token)"
        if len(out_obj) != 3:
            return False, None, "custom_codeblock must return exactly 3 elements in order: payload1, payload2, csrf_token"
        # return normalized three-tuple
        try:
            return True, (out_obj[0], out_obj[1], out_obj[2]), None
        except Exception as e:
            return False, None, "Error normalizing return value: %s" % e



    def extract_param_from_request(self, messageInfo, param_name):
        """
        Tries to extract parameter by name from the request's parameters.
        If not found, falls back to returning request body as string.
        """
        try:
            if not param_name:
                return ""
            try:
                analyzedReq = self.helpers.analyzeRequest(messageInfo)
            except:
                analyzedReq = None
            if analyzedReq:
                try:
                    params = analyzedReq.getParameters()
                    for p in params:
                        try:
                            if p.getName() == param_name:
                                try:
                                    return p.getValue()
                                except:
                                    return ""
                        except:
                            pass
                except:
                    pass
            # fallback: return whole body (if present)
            try:
                rb = messageInfo.getRequest()
                if rb:
                    return self.helpers.bytesToString(rb)
            except:
                pass
        except:
            pass
        return ""

    def _handle_external_payload(self, raw_request_bytes):
        """
        Robust, defensive rework of the original handler.
        Returns Python bytes (never str). On any error returns a small fallback HTTP response.
        """
        import sys, time, traceback

        # Normalize template text helper (place this inside _handle_external_payload, before any string->bytes conversion)
        def _normalize_template_text(text):
            # Ensure simple HTTP/2 -> HTTP/1.1 fallback for plain-text templates
            try:
                parts = text.split("\r\n", 1)
                if len(parts) >= 1:
                    first_line = parts[0].strip()
                    if first_line.upper().endswith("HTTP/2"):
                        first_line = first_line.rsplit(" ", 1)[0] + " HTTP/1.1"
                        text = first_line + ("\r\n" + parts[1] if len(parts) > 1 else "")
            except:
                pass

            # Add Connection: close if missing to avoid persistent-connection surprises
            try:
                if "connection:" not in text.lower():
                    text = text.replace("\r\n\r\n", "\r\nConnection: close\r\n\r\n", 1)
            except:
                pass

            return text


        def _log(msg):
            try:
                print("[FPL_RESP]", msg)
                sys.stdout.flush()
            except:
                pass
            try:
                with open("/tmp/fpl_resp_debug.log", "a") as f:
                    f.write("[%s] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), str(msg)))
            except:
                pass

        # fallback response bytes
        fallback_body = b"BoberProxy local server OK\n"
        fallback_resp = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
            + str(len(fallback_body)).encode("ascii")
            + b"\r\nConnection: close\r\n\r\n"
            + fallback_body
        )

        try:
            _log("ENTER handler raw len: %d" % (0 if raw_request_bytes is None else (len(raw_request_bytes) if hasattr(raw_request_bytes, "__len__") else -1)))
            if not raw_request_bytes:
                _log("No raw_request_bytes -> fallback")
                return fallback_resp

            # try to decode request text for parsing (logs only)
            try:
                req_text = raw_request_bytes.decode("latin-1", "replace")
            except:
                req_text = str(raw_request_bytes)

            # --- 1) determine payload param names (defensive) ---
            # --- extract incoming payloads (map q -> payload1, w -> payload2) ---
            try:
                pname1 = str(self.payloadParamField.getText()).strip()
            except:
                pname1 = getattr(self, "payload_param_name", "q")
            try:
                pname2 = str(self.payloadParam2Field.getText()).strip()
            except:
                pname2 = getattr(self, "payload_param2_name", "w")

            # extract from query or body similar to existing logic (ensure both may be empty then fallback to request text)
            incoming_payload1 = ""
            incoming_payload2 = ""
            # --- parse query for both names ---
            try:
                first_line = req_text.split("\r\n", 1)[0]
                parts = first_line.split()
                if len(parts) >= 2:
                    path = parts[1]
                    if "?" in path:
                        qstr = path.split("?", 1)[1]
                        for kv in qstr.split("&"):
                            if "=" in kv:
                                k, v = kv.split("=", 1)
                                if k == pname1 and not incoming_payload1:
                                    incoming_payload1 = v
                                elif k == pname2 and not incoming_payload2:
                                    incoming_payload2 = v
            except:
                pass

            # check body if still missing (form-urlencoded preferred)
            try:
                if incoming_payload1 == "" or incoming_payload2 == "":
                    hdr_body_split = req_text.split("\r\n\r\n", 1)
                    body_text = hdr_body_split[1] if len(hdr_body_split) > 1 else ""
                    content_type = ""
                    headers_text = hdr_body_split[0] if len(hdr_body_split) > 0 else ""
                    for hl in headers_text.split("\r\n")[1:]:
                        if hl.lower().startswith("content-type:"):
                            content_type = hl.split(":",1)[1].strip().lower()
                            break
                    if content_type.startswith("application/x-www-form-urlencoded"):
                        for kv in body_text.split("&"):
                            if "=" in kv:
                                k, v = kv.split("=", 1)
                                if k == pname1 and incoming_payload1 == "":
                                    incoming_payload1 = v
                                elif k == pname2 and incoming_payload2 == "":
                                    incoming_payload2 = v
                    if incoming_payload1 == "" and body_text:
                        incoming_payload1 = body_text
                    # do not override payload2 with body_text unless specifically set earlier (keep it empty if not present)
            except:
                pass

            # --- Follow-redirects direct-forward branch (robust, uses helpers.analyzeRequest + buildHttpMessage) ---
            # Insert this block immediately after the code that sets:
            #   incoming_payload1 = ...   (final fallback)
            #   incoming_payload2 = incoming_payload2 or ""
            # and before any template marker replacement or custom-code invocation.
            try:
                # read follow-redirects flag
                try:
                    follow_requested = bool(self.followRedirectsChk.isSelected())
                except Exception:
                    follow_requested = False

                # check whether the tool actually provided payloads (q/w or overrides)
                try:
                    tool_sent_payload1 = bool(incoming_payload1 and str(incoming_payload1).strip())
                except Exception:
                    tool_sent_payload1 = False
                try:
                    tool_sent_payload2 = bool(incoming_payload2 and str(incoming_payload2).strip())
                except Exception:
                    tool_sent_payload2 = False

                # if follow requested AND NO payloads were supplied by the tool -> take alternate direct-forward path
                if follow_requested and (not tool_sent_payload1 and not tool_sent_payload2):
                    # read UI target values with validation/fallbacks
                    try:
                        scheme = str(self.schemeField.getText()).strip().lower()
                    except Exception:
                        scheme = "http"
                    if scheme not in ("http", "https"):
                        scheme = "http"

                    try:
                        target_host_ui = str(self.targetHostField.getText()).strip()
                    except Exception:
                        target_host_ui = ""

                    try:
                        port_txt = str(self.targetPortField.getText()).strip()
                        port_val = int(port_txt)
                        if port_val < 1 or port_val > 65535:
                            raise ValueError("port out of range")
                    except Exception:
                        port_val = 443 if scheme == "https" else 80

                    # if no UI host configured, do not take this branch
                    if not target_host_ui:
                        pass
                    else:
                        req_bytes_to_send = None
                        try:
                            # Prefer parsing original raw bytes to rebuild headers/body safely
                            parsed_req = None
                            try:
                                if raw_request_bytes:
                                    parsed_req = self.helpers.analyzeRequest(raw_request_bytes)
                            except Exception:
                                parsed_req = None

                            if parsed_req:
                                # extract headers and body bytes
                                try:
                                    orig_headers = list(parsed_req.getHeaders())
                                except Exception:
                                    orig_headers = []
                                try:
                                    bo = parsed_req.getBodyOffset()
                                    orig_body = raw_request_bytes[bo:] if raw_request_bytes is not None else b""
                                except Exception:
                                    orig_body = b""

                                # build new headers: replace Host (respecting port) and ensure Connection: close
                                new_headers = []
                                host_replaced = False
                                for h in orig_headers:
                                    try:
                                        hs = str(h)
                                    except Exception:
                                        hs = h
                                    if hs.lower().startswith("host:"):
                                        if (scheme == "https" and port_val != 443) or (scheme == "http" and port_val != 80):
                                            new_headers.append("Host: %s:%d" % (target_host_ui, port_val))
                                        else:
                                            new_headers.append("Host: %s" % (target_host_ui))
                                        host_replaced = True
                                    elif hs.lower().startswith("connection:"):
                                        # normalize connection header
                                        new_headers.append("Connection: close")
                                    else:
                                        new_headers.append(hs)
                                if not host_replaced:
                                    if (scheme == "https" and port_val != 443) or (scheme == "http" and port_val != 80):
                                        new_headers.insert(0, "Host: %s:%d" % (target_host_ui, port_val))
                                    else:
                                        new_headers.insert(0, "Host: %s" % target_host_ui)

                                # ensure Connection present
                                if not any(h.lower().startswith("connection:") for h in new_headers):
                                    new_headers.append("Connection: close")

                                # let Burp build a correct HTTP message (handles request-line, content-length, etc.)
                                try:
                                    req_bytes_to_send = self.helpers.buildHttpMessage(new_headers, orig_body)
                                except Exception:
                                    # fallback: build from headers + body as bytes
                                    try:
                                        hdrs_text = "\r\n".join(new_headers) + "\r\n\r\n"
                                        req_bytes_to_send = self.helpers.stringToBytes(hdrs_text) + (orig_body if isinstance(orig_body, (bytes, bytearray)) else b"")
                                    except Exception:
                                        req_bytes_to_send = None
                            else:
                                # parsed_req not available: attempt to derive path from analyzeRequest or default to "/"
                                try:
                                    path = "/"
                                    try:
                                        if raw_request_bytes:
                                            pr = self.helpers.analyzeRequest(raw_request_bytes)
                                            url = pr.getUrl()
                                            if url:
                                                q = url.getQuery()
                                                path = url.getPath() + (("?" + q) if q else "")
                                    except Exception:
                                        path = "/"
                                    text_min = "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (path, target_host_ui)
                                    try:
                                        req_bytes_to_send = self.helpers.stringToBytes(text_min)
                                    except Exception:
                                        req_bytes_to_send = text_min.encode("latin-1", "replace")
                                except Exception:
                                    req_bytes_to_send = None
                        except Exception:
                            req_bytes_to_send = None

                        # if we have bytes to send, perform the request via Burp and return the response raw bytes unchanged
                        if req_bytes_to_send:
                            try:
                                # build service and send
                                try:
                                    svc = self.helpers.buildHttpService(target_host_ui, int(port_val), "https" if scheme == "https" else "http")
                                    try:
                                        resp_obj = self.callbacks.makeHttpRequest(svc, req_bytes_to_send)
                                    except Exception:
                                        try:
                                            resp_obj = self.callbacks.makeHttpRequest(target_host_ui, int(port_val), bool(scheme == "https"), req_bytes_to_send)
                                        except Exception:
                                            resp_obj = None
                                except Exception:
                                    resp_obj = None

                                if resp_obj:
                                    # poll for response (existing timing behavior)
                                    response_bytes = None
                                    attempts = 20
                                    sleep_s = 0.08
                                    for _ in range(attempts):
                                        try:
                                            response_bytes = resp_obj.getResponse()
                                        except Exception:
                                            response_bytes = None
                                        if response_bytes:
                                            break
                                        time.sleep(sleep_s)

                                    if response_bytes:
                                        # convert Java byte[] iterable to Python bytes safely
                                        try:
                                            if isinstance(response_bytes, (bytes, bytearray)):
                                                outb = bytes(response_bytes)
                                            else:
                                                out_arr = bytearray()
                                                for b in response_bytes:
                                                    try:
                                                        iv = int(b)
                                                    except Exception:
                                                        try:
                                                            iv = ord(b)
                                                        except Exception:
                                                            iv = 0
                                                    if iv < 0:
                                                        iv += 256
                                                    out_arr.append(iv)
                                                outb = bytes(out_arr)
                                        except Exception:
                                            try:
                                                s = self.helpers.bytesToString(response_bytes)
                                                outb = s.encode("latin-1", "replace")
                                            except Exception:
                                                outb = None

                                        if outb:
                                            # return raw response bytes directly to the local client (no template processing)
                                            return outb
                            except Exception:
                                # any error while sending/receiving -> fall back to normal template flow
                                pass
            except Exception:
                # top-level safety: ensure normal processing continues on unexpected errors
                pass
            # --- end follow-redirects branch ---


            # final fallback: use whole request string for payload1 if empty
            if incoming_payload1 == "":
                try:
                    incoming_payload1 = self.helpers.bytesToString(raw_request_bytes)
                except:
                    incoming_payload1 = str(raw_request_bytes)

            incoming_payload2 = incoming_payload2 or ""

            # decide csrf token to pass: if autoUpdateCsrf checked, obtain token (if any) else None
            # Always request the current CSRF token value, regardless of the checkbox state.
            csrf_token_to_pass = None
            try:
                csrf_name = str(self.csrfParamField.getText()).strip()
            except:
                csrf_name = getattr(self, "csrf_param_name", "csrfmiddlewaretoken")

            try:
                csrf_token_to_pass = self.csrfManager.get_token(csrf_name)
            except:
                try:
                    csrf_token_to_pass = getattr(self.csrfManager, "jar", {}).get(csrf_name)
                except:
                    csrf_token_to_pass = None
                
            # determine timeout (ms) to use for user code execution
            try:
                t_ms = int(self.timeoutField.getText())
            except Exception:
                t_ms = getattr(self, "custom_timeout_ms", 500)

            # run user code and enforce 3-value tuple out
            if csrf_token_to_pass is not None:
                ok, out, err = self.run_user_code(incoming_payload1, t_ms, incoming_payload2, csrf_token_to_pass)
            else:
                ok, out, err = self.run_user_code(incoming_payload1, t_ms, incoming_payload2, None)

            if ok and out is not None:
                # out must be a 3-tuple (payload1, payload2, csrf_token)
                if isinstance(out, (list, tuple)) and len(out) == 3:
                    outgoing_payload1 = out[0] or ""
                    outgoing_payload2 = out[1] or ""
                    returned_csrf = out[2]
                    # if autoUpdateCsrf checked and returned_csrf is not None -> update CsrfManager
                    if getattr(self, "autoUpdateCsrf", False) and returned_csrf is not None:
                        try:
                            csrf_name = str(self.csrfParamField.getText()).strip()
                        except:
                            csrf_name = getattr(self, "csrf_param_name", "csrfmiddlewaretoken")
                        try:
                            self.csrfManager.set_token(csrf_name, returned_csrf)
                        except:
                            try:
                                j = getattr(self.csrfManager, "jar", None)
                                if isinstance(j, dict):
                                    j[csrf_name] = returned_csrf
                            except:
                                pass
                else:
                    # user code violated contract -> treat as error: fall back to incoming values
                    try:
                        self.customStatusArea.setText("User code contract violation: must return exactly 3 values (payload1, payload2, csrf_token). Using original payloads.")
                    except:
                        pass
                    outgoing_payload1 = incoming_payload1
                    outgoing_payload2 = incoming_payload2
            else:
                # error or timeout -> fallback
                outgoing_payload1 = incoming_payload1
                outgoing_payload2 = incoming_payload2
                if not ok:
                    try:
                        if err is None:
                            self.customStatusArea.setText("User code: timeout")
                        else:
                            txt = str(err)
                            if len(txt) > 1000:
                                txt = txt[:1000] + "..."
                            self.customStatusArea.setText("User code error:\n%s" % txt)
                    except:
                        pass


            # --- 3) load and verify template ---
            try:
                if hasattr(self, "reqTemplateEditor"):
                    tb = self.reqTemplateEditor.getMessage()
                    if tb is None:
                        template_text = ""
                    else:
                        try:
                            template_text = self.helpers.bytesToString(tb)
                        except:
                            template_text = str(tb)
                else:
                    template_text = str(getattr(self, "reqTemplateArea", None) and self.reqTemplateArea.getText() or "")
            except:
                template_text = ""

            payload_marker = "p4yl04dm4rk3r"
            payload_marker2 = "53c0undm4rk3r"
            if not template_text.strip():
                try:
                    self.customStatusArea.setText("No Request Template configured; skipping template send.")
                except:
                    pass
                _log("RETURN: template empty")
                return fallback_resp

            if payload_marker not in template_text:
                try:
                    self.customStatusArea.setText("Request Template missing payload marker: %s" % payload_marker)
                except:
                    pass
                _log("RETURN: template missing marker")
                return fallback_resp

            final_request_text = template_text.replace("p4yl04dm4rk3r", outgoing_payload1)
            final_request_text = final_request_text.replace("53c0undm4rk3r", outgoing_payload2)
            _log("final_request_text length: %d" % len(final_request_text))

            # --- diagnostic: cookie jar before inject ---
            try:
                try:
                    _log("CookieManager.jar BEFORE inject: %s" % (self.cookieManager.dump()))
                except:
                    _log("CookieManager.jar BEFORE inject: <dump failed>")
            except:
                pass

            # --- inject cookies into the final request if enabled ---
            try:
                if getattr(self, "autoUpdateCookies", False):
                    try:
                        injected = self.cookieManager.inject_into_request(final_request_text)
                        if injected is None:
                            _log("CookieManager: inject_into_request returned None (in-place assumed)")
                        else:
                            final_request_text = injected
                        _log("CookieManager: injected cookies -> now final_request length: %d" % len(final_request_text))
                    except Exception as e:
                        _log("CookieManager inject error: %s" % str(e))
            except Exception:
                pass

            # --- DIAGNOSTIC LOG: cookie jar after inject ---
            try:
                try:
                    _log("CookieManager.jar AFTER inject: %s" % (self.cookieManager.dump()))
                except:
                    _log("CookieManager.jar AFTER inject: <dump failed>")
            except:
                pass

            # --- inject CSRF token marker c5rfm4rk3r if enabled ---
            try:
                if getattr(self, "autoUpdateCsrf", False):
                    try:
                        pname_csrf = str(self.csrfParamField.getText()).strip()
                    except:
                        pname_csrf = getattr(self, "csrf_param_name", "")
                    if pname_csrf:
                        token_val = self.csrfManager.get_token(pname_csrf)
                        if token_val is not None:
                            try:
                                final_request_text = final_request_text.replace("c5rfm4rk3r", token_val)
                                _log("CsrfManager: injected token for '%s' (len=%d)" % (pname_csrf, len(token_val)))
                            except Exception as e:
                                _log("CsrfManager inject error: %s" % str(e))
                        else:
                            _log("CsrfManager: no cached token for '%s' to inject" % pname_csrf)
            except Exception:
                pass

            # --- FORCE HTTPS DETECTION (insert immediately after loading template_text, BEFORE normalization) ---
            forced_https_flag = False
            try:
                # peek first request-line without mutating template_text
                first_line = ""
                try:
                    first_line = template_text.split("\r\n", 1)[0].strip()
                except:
                    first_line = ""

                # if template explicitly used HTTP/2, treat as intent to use TLS
                try:
                    if "HTTP/2" in first_line.upper():
                        forced_https_flag = True
                except:
                    pass

                # if the request-line uses an absolute https URL: GET https://host/path HTTP/1.1
                try:
                    toks = first_line.split()
                    if len(toks) >= 2:
                        maybe_url = toks[1].lower()
                        if maybe_url.startswith("https://"):
                            forced_https_flag = True
                            # optionally extract host/port now (we may still rely on analyzeRequest later)
                except:
                    pass

                # also detect explicit X-Force-Scheme header in template (optional user marker)
                try:
                    for ln in template_text.split("\r\n"):
                        if ln.lower().startswith("x-force-scheme:"):
                            v = ln.split(":",1)[1].strip().lower()
                            if v == "https":
                                forced_https_flag = True
                            break
                except:
                    pass

                # debug log for visibility
                try:
                    _log("forced_https_flag detected = %s, first_line='%s'" % (str(forced_https_flag), first_line))
                except:
                    pass
            except Exception:
                forced_https_flag = False
            # --- end FORCE HTTPS DETECTION ---


            try:
                final_request_text = _normalize_template_text(final_request_text)
            except:
                pass

            # --- 4) build request bytes and headers/body properly ---
            try:
                try:
                    request_bytes = self.helpers.stringToBytes(final_request_text)
                except:
                    request_bytes = final_request_text.encode("latin-1")
            except Exception:
                request_bytes = final_request_text.encode("latin-1")

            # Try parse with helpers to get headers and body
            headers = []
            body_bytes = b""
            try:
                parsed_req = self.helpers.analyzeRequest(request_bytes)
                headers = list(parsed_req.getHeaders())
                bo = parsed_req.getBodyOffset()
                body_bytes = request_bytes[bo:]
            except Exception:
                try:
                    s = request_bytes
                    sep = b"\r\n\r\n"
                    idx = s.find(sep)
                    if idx >= 0:
                        hdrs_block = s[:idx].decode("latin-1", "replace").split("\r\n")
                        headers = hdrs_block
                        body_bytes = s[idx+4:]
                    else:
                        headers = []
                        body_bytes = b""
                except:
                    headers = []
                    body_bytes = b""

            # Fix Content-Length if present or add it
            new_headers = []
            cl_handled = False
            for h in headers:
                try:
                    hs = str(h)
                    if hs.lower().startswith("content-length:"):
                        new_headers.append("Content-Length: %d" % len(body_bytes))
                        cl_handled = True
                    else:
                        new_headers.append(hs)
                except:
                    try:
                        new_headers.append(str(h))
                    except:
                        pass
            if not cl_handled and len(body_bytes) > 0:
                new_headers.append("Content-Length: %d" % len(body_bytes))

            try:
                request_bytes = self.helpers.buildHttpMessage(new_headers, body_bytes)
            except Exception:
                # keep current request_bytes if build fails
                pass

            # --- 5) determine target host/port/protocol ---
            target_host = None
            target_port = None
            target_https = False
            try:
                parsed_req2 = self.helpers.analyzeRequest(request_bytes)
                url = parsed_req2.getUrl()
                if url:
                    target_host = url.getHost()
                    target_port = url.getPort()
                    proto = url.getProtocol()
                    target_https = (str(proto).lower() == "https")
            except:
                pass


            # --- APPLY forced_https_flag if present and no explicit https detected ---
            try:
                # If we detected intent from template but parsed result did not indicate https, enforce it
                if forced_https_flag:
                    try:
                        # If parsed code set target_https already, keep it; otherwise force it
                        if not target_https:
                            target_https = True
                            if not target_port or int(target_port) <= 0:
                                target_port = 443
                            _log("forced_https_flag: forcing target to https on %s:%s" % (str(target_host), str(target_port)))
                    except Exception:
                        try:
                            target_https = True
                            target_port = 443
                        except:
                            pass
            except Exception:
                pass
            # --- end APPLY forced_https_flag ---


            # fallback: Host: header from template or original
            if not target_host:
                try:
                    txt = final_request_text
                    for line in txt.split("\r\n"):
                        if line.lower().startswith("host:"):
                            host_val = line.split(":",1)[1].strip()
                            if ":" in host_val:
                                h,p = host_val.split(":",1)
                                target_host = h.strip()
                                try:
                                    target_port = int(p.strip())
                                except:
                                    target_port = 443 if "https" in line.lower() else 80
                            else:
                                target_host = host_val
                                target_port = 443 if "https" in line.lower() else 80
                            break
                except:
                    pass

            if not target_host:
                try:
                    for line in req_text.split("\r\n"):
                        if line.lower().startswith("host:"):
                            host_val = line.split(":",1)[1].strip()
                            if ":" in host_val:
                                h,p = host_val.split(":",1)
                                target_host = h.strip()
                                try:
                                    target_port = int(p.strip())
                                except:
                                    target_port = 80
                            else:
                                target_host = host_val
                                target_port = 80
                            break
                except:
                    pass

            # --- CONSISTENCY FIX: if we forced https, ensure port is consistent with https
            try:
                # If forced https but host was only discovered via Host header and port is 80 (or missing),
                # prefer port 443 so we don't attempt TLS on port 80.
                if forced_https_flag:
                    try:
                        # If no host was known earlier but we discovered it via fallback, ensure port aligns
                        if target_host and (not target_port or int(target_port) == 80):
                            target_port = 443
                            _log("forced_https_flag: adjusted port to 443 for host=%s" % str(target_host))
                    except Exception:
                        try:
                            target_port = 443
                        except:
                            pass
            except Exception:
                pass
            # --- end consistency fix ---


            if not target_host:
                try:
                    self.customStatusArea.setText("Unable to determine target host for template request; skipping send.")
                except:
                    pass
                _log("RETURN: no target_host")
                return fallback_resp

            if not target_port:
                target_port = 443 if target_https else 80


            # --- DIAGNOSTIC: final send decision ---
            try:
                _log("FINAL SEND DECISION: host=%s port=%s target_https=%s (forced_https=%s)" %
                    (str(target_host), str(target_port), str(bool(target_https)), str(bool(forced_https_flag))))
            except:
                pass
            # --- end diagnostic ---


            _log("Will send to %s:%s https=%s" % (target_host, target_port, target_https))

            # --- 6) send via Burp callbacks.makeHttpRequest ---
            try:
                resp_obj = None
                try:
                    svc = self.helpers.buildHttpService(target_host, int(target_port), "https" if target_https else "http")
                    resp_obj = self.callbacks.makeHttpRequest(svc, request_bytes)
                except Exception:
                    try:
                        resp_obj = self.callbacks.makeHttpRequest(target_host, int(target_port), bool(target_https), request_bytes)
                    except Exception:
                        resp_obj = None

                if not resp_obj:
                    try:
                        self.customStatusArea.setText("makeHttpRequest failed (no resp object).")
                    except:
                        pass
                    _log("RETURN: resp_obj is None")
                    return fallback_resp

                # poll getResponse()
                response_bytes = None
                attempts = 20
                sleep_s = 0.08
                for i in range(attempts):
                    try:
                        response_bytes = resp_obj.getResponse()
                    except Exception as e:
                        _log("getResponse() exception: %s" % str(e))
                        response_bytes = None
                    if response_bytes:
                        # update cookie jar
                        try:
                            if getattr(self, "autoUpdateCookies", False):
                                try:
                                    changes = self.cookieManager.update_from_response(response_bytes)
                                    if changes:
                                        for ch in changes:
                                            try:
                                                self.customStatusArea.setText("Cookie update: %s -> %s" % (ch[1], ch[3]))
                                            except:
                                                pass
                                        _log("CookieManager: updated from response: %s" % str(changes))
                                except Exception as e:
                                    _log("CookieManager update error: %s" % str(e))
                        except Exception:
                            pass

                        # CSRF extraction
                        try:
                            if getattr(self, "autoUpdateCsrf", False):
                                pname_csrf = ""
                                try:
                                    pname_csrf = str(self.csrfParamField.getText()).strip()
                                except:
                                    pname_csrf = self.csrf_param_name
                                if pname_csrf:
                                    try:
                                        custom_pat = str(self.csrfRegexArea.getText() or "").strip()
                                        if custom_pat:
                                            self.csrfManager.pattern_to_use = custom_pat
                                        else:
                                            self.csrfManager.pattern_to_use = None
                                    except:
                                        self.csrfManager.pattern_to_use = None
                                    try:
                                        ok, val = self.csrfManager.update_from_response(response_bytes, pname_csrf)
                                        if ok:
                                            _log("CsrfManager: extracted token for '%s' (len=%d)" % (pname_csrf, len(val)))
                                            try:
                                                self.customStatusArea.setText("CSRF token updated: %s" % (pname_csrf))
                                            except:
                                                pass
                                        else:
                                            _log("CsrfManager: no token found for '%s' in response" % pname_csrf)
                                    except Exception as e:
                                        _log("CsrfManager update_from_response exception: %s" % str(e))
                        except Exception:
                            pass

                        _log("getResponse succeeded on attempt %d, len guess=%d" % (i, (len(response_bytes) if hasattr(response_bytes, "__len__") else -1)))
                        break

                    time.sleep(sleep_s)

                if not response_bytes:
                    try:
                        self.customStatusArea.setText("No response bytes returned from target.")
                    except:
                        pass
                    _log("RETURN: no response_bytes after polling")
                    return fallback_resp

                # Convert Java byte[] (iterable with possibly signed ints) to Python bytes
                try:
                    if isinstance(response_bytes, (bytes, bytearray)):
                        outb = bytes(response_bytes)
                        _log("response already bytes-like, len=%d" % len(outb))
                        try:
                            self.customStatusArea.setText("Template sent and response forwarded (raw).")
                        except:
                            pass
                        return outb

                    # CheckPageTemplate follow-up (before conversion)
                    try:
                        if getattr(self, "useCheckPageTemplate", False):
                            try:
                                if hasattr(self, "checkPageEditor"):
                                    cb = self.checkPageEditor.getMessage()
                                    if cb is None:
                                        check_tmpl = ""
                                    else:
                                        try:
                                            check_tmpl = self.helpers.bytesToString(cb)
                                        except:
                                            check_tmpl = str(cb)
                                else:
                                    check_tmpl = str(getattr(self, "checkPageArea", None) and self.checkPageArea.getText() or "")
                            except:
                                check_tmpl = ""
                            if check_tmpl:
                                _log("CheckPageTemplate: preparing follow-up request")
                                final_check = check_tmpl
                                try:
                                    final_check = final_check.replace("p4yl04dm4rk3r", outgoing_payload1)
                                except:
                                    pass
                                try:
                                    final_check = final_check.replace("53c0undm4rk3r", outgoing_payload2)
                                except:
                                    pass
                                try:
                                    injected = self.cookieManager.inject_into_request(final_check)
                                    if injected is None:
                                        _log("CheckPageTemplate: cookie inject returned None (in-place assumed)")
                                    else:
                                        final_check = injected
                                    _log("CheckPageTemplate: cookies injected (or attempted)")
                                except Exception as e:
                                    _log("CheckPageTemplate: cookie injection failed: %s" % str(e))

                                try:
                                    token_name = str(self.csrfParamField.getText()).strip() if hasattr(self, "csrfParamField") else getattr(self, "csrf_param_name", "")
                                except:
                                    token_name = getattr(self, "csrf_param_name", "")
                                try:
                                    token_val = None
                                    if token_name:
                                        try:
                                            token_val = self.csrfManager.get_token(token_name)
                                        except:
                                            try:
                                                token_val = getattr(self.csrfManager, "jar", {}).get(token_name)
                                            except:
                                                token_val = None
                                    if token_val:
                                        final_check = final_check.replace("c5rfm4rk3r", token_val)
                                        _log("CheckPageTemplate: CSRF token inserted for '%s'" % token_name)
                                except Exception as e:
                                    _log("CheckPageTemplate: csrf insertion error: %s" % str(e))


                                # --- FORCE HTTPS DETECTION (insert immediately after loading template_text, BEFORE normalization) ---
                                forced_https_flag = False
                                try:
                                    # peek first request-line without mutating template_text
                                    first_line = ""
                                    try:
                                        first_line = template_text.split("\r\n", 1)[0].strip()
                                    except:
                                        first_line = ""

                                    # if template explicitly used HTTP/2, treat as intent to use TLS
                                    try:
                                        if "HTTP/2" in first_line.upper():
                                            forced_https_flag = True
                                    except:
                                        pass

                                    # if the request-line uses an absolute https URL: GET https://host/path HTTP/1.1
                                    try:
                                        toks = first_line.split()
                                        if len(toks) >= 2:
                                            maybe_url = toks[1].lower()
                                            if maybe_url.startswith("https://"):
                                                forced_https_flag = True
                                                # optionally extract host/port now (we may still rely on analyzeRequest later)
                                    except:
                                        pass

                                    # also detect explicit X-Force-Scheme header in template (optional user marker)
                                    try:
                                        for ln in template_text.split("\r\n"):
                                            if ln.lower().startswith("x-force-scheme:"):
                                                v = ln.split(":",1)[1].strip().lower()
                                                if v == "https":
                                                    forced_https_flag = True
                                                break
                                    except:
                                        pass

                                    # debug log for visibility
                                    try:
                                        _log("forced_https_flag detected = %s, first_line='%s'" % (str(forced_https_flag), first_line))
                                    except:
                                        pass
                                except Exception:
                                    forced_https_flag = False
                                # --- end FORCE HTTPS DETECTION ---


                                try:
                                    final_check = _normalize_template_text(final_check)
                                except:
                                    pass

                                try:
                                    req_bytes = self.helpers.stringToBytes(final_check)
                                except Exception:
                                    try:
                                        req_bytes = final_check.encode("latin-1")
                                    except:
                                        req_bytes = None

                                if req_bytes is not None:
                                    _log("CheckPageTemplate: Will send check request to %s:%s https=%s" % (target_host, target_port, str(target_https)))
                                    check_resp = None
                                    try:
                                        try:
                                            svc2 = self.helpers.buildHttpService(target_host, int(target_port), "https" if target_https else "http")
                                            check_resp_msg = self.callbacks.makeHttpRequest(svc2, req_bytes)
                                        except Exception:
                                            try:
                                                check_resp_msg = self.callbacks.makeHttpRequest(target_host, int(target_port), bool(target_https), req_bytes)
                                            except Exception as e:
                                                check_resp_msg = None
                                                _log("CheckPageTemplate: makeHttpRequest failed: %s" % str(e))

                                        if check_resp_msg:
                                            check_attempts = 15
                                            check_sleep = 0.06
                                            for ci in range(check_attempts):
                                                try:
                                                    cr = check_resp_msg.getResponse()
                                                except Exception as e:
                                                    _log("CheckPageTemplate: getResponse() exception: %s" % str(e))
                                                    cr = None
                                                if cr:
                                                    check_resp = cr
                                                    break
                                                time.sleep(check_sleep)
                                    except Exception as e:
                                        _log("CheckPageTemplate: make/send exception: %s" % str(e))

                                    if check_resp:
                                        try:
                                            if getattr(self, "autoUpdateCookies", False):
                                                try:
                                                    changes2 = self.cookieManager.update_from_response(check_resp)
                                                    _log("CheckPageTemplate: cookie changes from check response: %s" % str(changes2))
                                                except:
                                                    pass
                                        except:
                                            pass
                                        try:
                                            _ = self.csrfManager.update_from_response(check_resp)
                                        except:
                                            pass
                                        response_bytes = check_resp
                                        _log("CheckPageTemplate: using check response instead of original response")
                                    else:
                                        _log("CheckPageTemplate: no response from check request, keeping original response")
                    except Exception:
                        _log("CheckPageTemplate: unexpected error in follow-up flow",)

                    # conversion of iterable byte-like -> Python bytes
                    out_arr = bytearray()
                    for b in response_bytes:
                        try:
                            iv = int(b)
                        except Exception:
                            try:
                                iv = ord(b)
                            except Exception:
                                iv = 0
                        if iv < 0:
                            iv += 256
                        out_arr.append(iv)
                    outb = bytes(out_arr)
                    _log("Converted response iterable -> len=%d" % len(outb))
                    try:
                        self.customStatusArea.setText("Template sent and response forwarded (raw).")
                    except:
                        pass
                    return outb

                except Exception as e:
                    _log("conversion failed: %s" % str(e))
                    try:
                        s = self.helpers.bytesToString(response_bytes)
                        _log("helpers.bytesToString len=%d" % (len(s) if s is not None else 0))
                    except Exception as e2:
                        _log("helpers.bytesToString failed: %s" % str(e2))
                    _log("RETURN: conversion failed -> fallback")
                    return fallback_resp

            except Exception as e:
                try:
                    self.customStatusArea.setText("Network error sending template: %s" % str(e))
                except:
                    pass
                _log("SEND BLOCK EXCEPTION: %s" % str(e))
                try:
                    traceback.print_exc()
                except:
                    pass
                _log("RETURN: network/send exception -> fallback")
                return fallback_resp

        except Exception as e:
            try:
                self.customStatusArea.setText("Internal handler error: %s" % str(e))
            except:
                pass
            _log("TOP-LEVEL EXCEPTION: %s" % str(e))
            try:
                traceback.print_exc()
            except:
                pass
            _log("RETURN: top-level exception -> fallback")
            return fallback_resp

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        callbacks.setExtensionName("BoberProxy")
        self.helpers = callbacks.getHelpers()

        self.controller = SimpleMessageController()
        try:
            self.msgEditor = callbacks.createMessageEditor(self.controller, False)
        except Exception as e:
            print("createMessageEditor failed (ignored):", e)
            self.msgEditor = None

        self.ui = LoggerUI(callbacks, self.controller, self.msgEditor, callbacks)
        callbacks.addSuiteTab(self.ui)

        callbacks.registerHttpListener(self)
        print("BoberProxy loaded")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            host = method = path = ""
            status = None
            length = None
            try:
                if messageIsRequest:
                    analyzed = self.helpers.analyzeRequest(messageInfo)
                    method = analyzed.getMethod()
                    url = analyzed.getUrl()
                    if url:
                        host = url.getHost()
                        q = url.getQuery()
                        path = url.getPath() + (("?" + q) if q else "")
                    reqb = messageInfo.getRequest()
                    length = len(reqb) if reqb else 0
                else:
                    respb = messageInfo.getResponse()
                    if respb:
                        analyzedResp = self.helpers.analyzeResponse(respb)
                        try:
                            status = analyzedResp.getStatusCode()
                        except:
                            status = None
                        length = len(respb)
                    try:
                        analyzedReq = self.helpers.analyzeRequest(messageInfo)
                        method = analyzedReq.getMethod()
                        url = analyzedReq.getUrl()
                        if url:
                            host = url.getHost()
                            q = url.getQuery()
                            path = url.getPath() + (("?" + q) if q else "")
                    except:
                        pass
            except:
                pass

            # --- Custom codeblock transform step (NEW) ---
            outgoing_payload_from_custom = None
            try:
                try:
                    use_custom = bool(self.ui.useCustomChk.isSelected())
                except:
                    use_custom = False
                if use_custom:
                    pname = ""
                    try:
                        pname = str(self.ui.payloadParamField.getText()).strip()
                    except:
                        pname = self.ui.payload_param_name
                    incoming_payload = self.ui.extract_param_from_request(messageInfo, pname)

                    # add:
                    pname2 = ""
                    try:
                        pname2 = str(self.ui.payloadParam2Field.getText()).strip()
                    except:
                        pname2 = getattr(self.ui, "payload_param2_name", "w")
                    incoming_payload2 = self.ui.extract_param_from_request(messageInfo, pname2)

                    try:
                        t_ms = int(self.ui.timeoutField.getText())
                    except:
                        t_ms = self.ui.custom_timeout_ms

                    # Always pass the current CSRF token value to the custom codeblock
                    try:
                        csrf_name = str(self.ui.csrfParamField.getText()).strip()
                    except:
                        csrf_name = getattr(self.ui, "csrf_param_name", "csrfmiddlewaretoken")

                    try:
                        cached_csrf = self.ui.csrfManager.get_token(csrf_name)
                    except:
                        try:
                            cached_csrf = getattr(self.ui.csrfManager, "jar", {}).get(csrf_name)
                        except:
                            cached_csrf = None

                    ok, out, err = self.ui.run_user_code(incoming_payload, t_ms, incoming_payload2, cached_csrf)

                    if ok and out is not None:
                        outgoing_payload_from_custom = out
                    else:
                        # show brief error in UI label (do not block)
                        try:
                            if err is None:
                                self.ui.customStatusLabel.setText("User code: timeout")
                            else:
                                # keep message short
                                txt = str(err)
                                if len(txt) > 200:
                                    txt = txt[:200] + "..."
                                self.ui.customStatusLabel.setText("User code error: %s" % txt)
                        except:
                            pass
                        outgoing_payload_from_custom = incoming_payload  # fallback
            except Exception:
                try:
                    self.ui.customStatusLabel.setText("User code error (internal)")
                except:
                    pass
                outgoing_payload_from_custom = None
            # Note: outgoing_payload_from_custom now contains the transformed payload (or fallback)
            # How to use it depends on the template insertion point — here we attach it to messageInfo metadata
            # so other code (template engine) can pick it up. For now, we just log it as part of the entry if present.

            try:
                should = self.ui.should_log(toolFlag, messageIsRequest, messageInfo)
            except:
                should = True

            if should:
                # attach transformed payload info into log entry (as 7th element) — non-invasive
                def _append():
                    try:
                        # For requests, show the outgoing_payload_from_custom (if set) in the detail view only when selected.
                        self.ui.append_log_row(toolFlag, host, method, path, status, length, messageInfo, messageIsRequest)
                        # Optionally annotate latest row's status label if transform exists
                        if outgoing_payload_from_custom is not None:
                            try:
                                self.ui.customStatusLabel.setText("Last transform applied")
                            except:
                                pass
                    except Exception as e:
                        print("append invoke error:", e)
                swing.SwingUtilities.invokeLater(_append)
        except Exception as e:
            print("processHttpMessage error:", e)
