# -*- coding: latin-1 -*-
# Extender.py — BoberProxy (updated: tabs, template controls, custom codeblock)
from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IMessageEditorController, IProxyListener

from javax import swing
from javax.swing import SortOrder, RowSorter, SwingUtilities, JTable, ListSelectionModel
from javax.swing.table import DefaultTableModel, TableRowSorter, AbstractTableModel
from javax.swing.text import DefaultHighlighter
from javax.swing.event import ChangeListener

from java.awt import (
    GridBagLayout, GridBagConstraints, Insets, Font, FlowLayout,
    Color, Dimension, BorderLayout
)
from java.awt.event import MouseAdapter, ComponentAdapter
from java.util import Comparator
from java.util.regex import Pattern
from java.lang import Integer

import sys, threading, time, os, socket, traceback, jarray, binascii, hashlib, re

# URL parsing – choose one, depending on which one works in your environment
# Python 2 (old Jython versions):
from urlparse import urljoin, urlparse
# Python 3 (Jython and newer versions):
#from urllib.parse import urljoin, urlparse

class LogEntry(object):
    def __init__(self, index, ts, host, method, path,
                 status, total_len, body_len, messageInfo):

        self.index = index
        self.ts = ts
        self.host = host
        self.method = method
        self.path = path
        self.status = status
        self.total_len = total_len
        self.body_len = body_len
        self.messageInfo = messageInfo


class LogStore:
    def __init__(self):
        self.entries = []
        self._counter = 0

    def add(self, ts, host, method, path, status,
            total_len, body_len, messageInfo):

        self._counter += 1

        e = LogEntry(
            index=self._counter,
            ts=ts,
            host=host,
            method=method,
            path=path,
            status=status,
            total_len=total_len,
            body_len=body_len,
            messageInfo=messageInfo
        )

        self.entries.insert(0, e)
        return e

    def clear(self):
        self.entries = []
        self._counter = 0


class LogTableModel(AbstractTableModel):

    COLUMNS = [
        "#", "Time", "Host", "Method", "Path",
        "Status", "Total Len", "Body Len"
    ]

    def __init__(self, logStore):
        AbstractTableModel.__init__(self)
        self.logStore = logStore
        self.displayed = []   # List[LogEntry]

    # ---------- JTable API ----------

    def getRowCount(self):
        return len(self.displayed)

    def getColumnCount(self):
        return len(self.COLUMNS)

    def getColumnName(self, col):
        return self.COLUMNS[col]

    def getValueAt(self, row, col):
        try:
            e = self.displayed[row]
            values = (
                Integer(e.index),
                e.ts,
                e.host,
                e.method,
                e.path,
                Integer(e.status) if e.status != "" else Integer(0),
                Integer(e.total_len) if e.total_len != "" else Integer(0),
                Integer(e.body_len) if e.body_len != "" else Integer(0),
            )
            return values[col]
        except:
            return ""

    def getColumnClass(self, col):
        if col in (0, 5, 6, 7):
            return Integer
        return str


    def isCellEditable(self, row, col):
        return False

    # ---------- Data control ----------

    def rebuild(self, filter_fn=None):
        if filter_fn:
            self.displayed = [
                e for e in self.logStore.entries
                if filter_fn(e)
            ]
        else:
            self.displayed = list(self.logStore.entries)

        self.fireTableDataChanged()


    def add_entry_top(self, entry, show):
        if not show:
            return

        self.displayed.insert(0, entry)

        # Swing értesítés
        self.fireTableRowsInserted(0, 0)


    def clear(self):
        self.displayed = []
        self.fireTableDataChanged()


class CsrfManager(object):

    def __init__(self):
        self.lock = threading.Lock()
        self.token = None             # there is only 1 token
        self.pattern_to_use = None    # user-specified regex

    def _decode(self, data):
        if isinstance(data, (bytes, bytearray)):
            try:
                return data.decode("latin-1", "replace")
            except:
                return data.decode("utf-8", "replace")

        try:
            if hasattr(data, "__iter__") and not isinstance(data, str):
                return bytearray((int(b) & 0xff for b in data)).decode("latin-1", "replace")
        except:
            pass

        try:
            return str(data)
        except:
            return ""

    def update_from_response(self, response_bytes):
        """
        Extract CSRF token using user regex.
        Returns (True, token) or (False, None)
        """
        txt = self._decode(response_bytes)
        if not txt:
            return False, None

        # user regex required
        pattern = self.pattern_to_use
        if not pattern:
            return False, None

        try:
            m = re.search(pattern, txt, flags=re.IGNORECASE | re.DOTALL)
            if not m:
                return False, None

            token = m.group(1)
            with self.lock:
                self.token = token
            return True, token

        except:
            return False, None

    def get_token(self):
        with self.lock:
            return self.token

    def set_token(self, value):
        with self.lock:
            self.token = value

    def clear(self):
        with self.lock:
            self.token = None

    def dump(self):
        with self.lock:
            return self.token or "<no csrf token>"


class CookieManager(object):
    """
    Clean, robust cookie handler for both proxy responses and internal flows.
    Thread-safe. API is fully backward-compatible.
    """

    def __init__(self):
        self.jar = {}   # {cookie_name: cookie_value}
        self.lock = threading.Lock()

    # --- Internal helper ---

    def _decode(self, data):
        """
        Minimal, deterministic conversion: because Burp always passes bytes.
        """
        if isinstance(data, (bytes, bytearray)):
            try:
                return data.decode("latin-1", "replace")
            except:
                return data.decode("utf-8", "replace")

        # Java byte[] masquerading as iterable of ints
        try:
            if hasattr(data, "__iter__") and not isinstance(data, str):
                ba = bytearray()
                for b in data:
                    try: ba.append(int(b) & 0xff)
                    except: pass
                return ba.decode("latin-1", "replace")
        except:
            pass

        # last fallback
        try:
            return str(data)
        except:
            return ""

    # --- Public API ---

    def update_from_response(self, response_bytes_or_text):
        """
        Parse Set-Cookie headers and update jar.
        Accepts bytes or string.
        Returns list of ("added"/"updated"/"deleted", name, old, new).
        """
        txt = self._decode(response_bytes_or_text)
        changes = []

        # isolate headers
        try:
            headers = txt.split("\r\n\r\n", 1)[0].split("\r\n")
        except:
            return changes

        for line in headers:
            if not line or "set-cookie" not in line.lower():
                continue

            try:
                # Remove "Set-Cookie:"
                val = line.split(":", 1)[1].strip()
                # Take only the name=value
                pair = val.split(";", 1)[0].strip()

                if "=" not in pair:
                    continue

                name, value = pair.split("=", 1)
                name = name.strip()
                value = value.strip()

                with self.lock:
                    old = self.jar.get(name)

                    # deletion
                    if value == "" or value.lower().startswith("deleted"):
                        if name in self.jar:
                            del self.jar[name]
                            changes.append(("deleted", name, old, None))
                        continue

                    # update or add
                    self.jar[name] = value
                    if old is None:
                        changes.append(("added", name, None, value))
                    else:
                        changes.append(("updated", name, old, value))

            except Exception:
                pass

        return changes

    def inject_into_request(self, request_text):
        """
        Merge current cookies into the request. Return new request text.
        """
        try:
            txt = str(request_text)
        except:
            txt = request_text.encode("latin-1", "replace")

        # split header/body
        parts = txt.split("\r\n\r\n", 1)
        header_lines = parts[0].split("\r\n")
        body = parts[1] if len(parts) > 1 else ""

        # existing cookies
        existing = {}
        new_header_lines = []
        found_cookie_hdr = False

        for h in header_lines:
            if h.lower().startswith("cookie:"):
                found_cookie_hdr = True
                try:
                    cookie_str = h.split(":", 1)[1].strip()
                    for pair in cookie_str.split(";"):
                        if "=" in pair:
                            k, v = pair.split("=", 1)
                            existing[k.strip()] = v.strip()
                except:
                    pass
            else:
                new_header_lines.append(h)

        # merge cookies (jar overrides)
        with self.lock:
            merged = dict(existing)
            merged.update(self.jar)

        # insert cookie header
        if merged:
            cookie_header = "Cookie: " + "; ".join("%s=%s" % (k, v) for k, v in merged.items())

            # try to insert right after Host:
            inserted = False
            for idx, h in enumerate(new_header_lines):
                if h.lower().startswith("host:"):
                    new_header_lines.insert(idx + 1, cookie_header)
                    inserted = True
                    break

            if not inserted:
                # fallback: after request-line
                if len(new_header_lines) > 1:
                    new_header_lines.insert(1, cookie_header)
                else:
                    new_header_lines.append(cookie_header)

        # rebuild request
        return "\r\n".join(new_header_lines) + "\r\n\r\n" + body


    def clear(self):
        with self.lock:
            self.jar = {}

    def dump(self):
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

        #------------------NEW---------------------------
        #  LogStore
        self.logStore = LogStore()

        #  LogTableModel
        self.logTableModel = LogTableModel(self.logStore)

        #  JTable
        self.table = JTable(self.logTableModel)
        self.table.setSelectionMode(
            ListSelectionModel.SINGLE_SELECTION
        )

        #  Sorter
        self.rowSorter = TableRowSorter(self.logTableModel)
        self.table.setRowSorter(self.rowSorter)
        self.table.setAutoCreateRowSorter(True)

        # 5 Selection listener
        self.table.getSelectionModel().addListSelectionListener(
            self.on_table_select
        )
        #------------------NEW---------------------------

        self._init_display_filters()

        # search / highlight state
        self._search_matches = []
        self._current_match_idx = -1

        # Proxy toggle state: when True, extension will intercept proxy requests and run the processing flow
        self._proxy_mode_active = False

        # other flags / storage
        self.paused = False
        self.running = False


        # Custom codeblock defaults
        self.default_code_text = (
            "def custom_codeblock(payload1, payload2, csrf_token):\n"
            "    \"\"\"\n"
            "    Custom transform hook that MUST accept and MUST return exactly three values.\n"
            "    Parameters\n"
            "    - payload1: first incoming payload (string)\n"
            "    - payload2: second incoming payload (string)\n"
            "    - csrf_token: csrf token (string)\n"
            "    MUST return exactly three elements in this order:\n"
            "    return payload1, payload2, csrf_token\n"
            "    \"\"\"\n"
            "    # Default behaviour: pass inputs through unchanged\n"
            "\n"
            "\n"
            "    return payload1, payload2, csrf_token\n"
        )

        self.custom_timeout_ms = 500
        self.payload_param_name = "q"

        # Cookie / CSRF managers + flags
        self.cookieManager = CookieManager()
        self.autoUpdateCookies = False

        self.csrfManager = CsrfManager()
        self.autoUpdateCsrf = False

        # default CSRF regex pattern (use %s for insertion of param name)
        self.csrf_default_pattern = r'<input[^>]+name=["\\\']csrfmiddlewaretoken["\\\'][^>]*value=["\\\']([^"\\\']*)["\\\']'

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
        # prefer the msgEditor passed in (existing), but create separate viewers via callbacks if available
        self.reqViewer = callbacks.createMessageEditor(self.controller, False)
        self.respViewer = callbacks.createMessageEditor(self.controller, False)
        # obtain Swing components
        reqComp = self.reqViewer.getComponent()
        respComp = self.respViewer.getComponent()


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
        self.reqTemplateEditor = callbacks.createMessageEditor(self._template_req_controller, True)
        self.reqTemplateComp = self.reqTemplateEditor.getComponent()


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

        rpc.gridx = 2
        rpc.weightx = 0.0
        rpc.anchor = GridBagConstraints.EAST
        rowPanel.add(btnPanel, rpc)


        # add the single-row panel into the template panel (same grid row as before)
        rtc.gridy = 1; rtc.weighty = 0.0; rtc.fill = GridBagConstraints.HORIZONTAL
        reqTemplatePanel.add(rowPanel, rtc)


        # === CheckPageTemplate: use Burp IMessageEditor (editable) ===
        self._template_check_controller = SimpleMessageController()
        self.checkPageEditor = callbacks.createMessageEditor(self._template_check_controller, True)
        self.checkPageComp = self.checkPageEditor.getComponent()
 
        # CheckPageTemplate panel
        checkPagePanel = swing.JPanel(GridBagLayout())
        cpc = GridBagConstraints()
        cpc.insets = Insets(2,2,2,2)
        cpc.fill = GridBagConstraints.BOTH
        cpc.weightx = 1.0
        cpc.weighty = 1.0
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

        self.leftSplit.setLeftComponent(self.tabbed)


        self.table.setSelectionMode(swing.ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self.table.getSelectionModel().addListSelectionListener(self.on_table_select)

        self.leftSplit.setRightComponent(swing.JScrollPane(self.table))

        # attach left split to main split
        self.mainSplit.setLeftComponent(self.leftSplit)

        # ---------- RIGHT: controls (mode + filters + utility) ----------
        # We'll use a GridBagLayout for overall placement, but make groups use horizontal Box/Flow where needed
        rightWrapper = swing.JPanel()
        rightWrapper.setLayout(swing.BoxLayout(rightWrapper, swing.BoxLayout.Y_AXIS))        

        # Inner grid content (kept same as before)        
        rightContent = swing.JPanel(GridBagLayout())
        # FIX minimum width – NO dynamic resizing
        rightContent.setMinimumSize(Dimension(610, 0))
        c = GridBagConstraints()
        c.insets = Insets(4,4,4,4)
        c.fill = GridBagConstraints.HORIZONTAL
        c.weightx = 0.5
        row = 0

        # Mode selector (proxy / local)
        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        modePanel = swing.JPanel()
        self.proxyModeBtn = swing.JToggleButton("Injecting proxy from templates", False, actionPerformed=lambda e: self._on_proxy_toggle())
        modePanel.add(self.proxyModeBtn)
        rightContent.add(modePanel, c)
        row += 1

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
        rightContent.add(swing.JLabel("Response regex (Java Pattern, .find() must match):"), c)
        row += 1
        c.gridy = row
        self.regexField = swing.JTextField("", 20)
        self.regexField.setToolTipText("Uses Java regex (java.util.regex.Pattern); escape backslashes (\\w, \\d, etc.); evaluated with .find(), not .matches().")

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


        # instantiate:
        self.useCheckPageChk = swing.JCheckBox("Use CheckPageTemplate", False, actionPerformed=self._on_use_checkpage_toggle)
        self.useCheckPageTemplate = False

        self.autoFollowRTChk = swing.JCheckBox("AutoFollow redirect on RT", False)
        self.autoFollowRTChk.setEnabled(False)

        # add to UI in one row:
        c.gridy = row
        c.gridx = 0
        rightContent.add(self.useCheckPageChk, c)
        c.gridx = 1
        rightContent.add(self.autoFollowRTChk, c)
        row += 1


        # --- Cookies checkbox ---
        self.autoUpdateChk = swing.JCheckBox(
            "Auto-update cookies from responses", False,
            actionPerformed=lambda e: setattr(self, "autoUpdateCookies", bool(self.autoUpdateChk.isSelected()))
        )

        # --- CSRF checkbox ---
        self.autoUpdateCsrfChk = swing.JCheckBox(
            "Auto-update CSRF from responses", False,
            actionPerformed=lambda e: setattr(self, "autoUpdateCsrf", bool(self.autoUpdateCsrfChk.isSelected()))
        )

        # --- Cookies buttons ---
        cookiePanel = swing.JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        self.clearCookiesBtn = swing.JButton("Clear Cookies", actionPerformed=lambda e: self._on_clear_cookies())
        cookiePanel.add(self.clearCookiesBtn)
        self.showCookiesBtn = swing.JButton("Show Cookies", actionPerformed=lambda e: self._on_show_cookies())
        cookiePanel.add(self.showCookiesBtn)
        cookiePanel.setMaximumSize(cookiePanel.getPreferredSize())

        # --- CSRF buttons ---
        csrfPanel = swing.JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        self.clearCsrfBtn = swing.JButton("Clear CSRF", actionPerformed=lambda e: self._on_clear_csrf())
        csrfPanel.add(self.clearCsrfBtn)
        self.showCsrfBtn = swing.JButton("Show CSRF", actionPerformed=lambda e: self._on_show_csrf())
        csrfPanel.add(self.showCsrfBtn)
        csrfPanel.setMaximumSize(csrfPanel.getPreferredSize())


        # --- Elrendezés: két sor, két oszlop ---
        # sor 1: checkboxok
        c.gridy = row; c.gridx = 0
        rightContent.add(self.autoUpdateChk, c)
        c.gridx = 1
        rightContent.add(self.autoUpdateCsrfChk, c)
        row += 1

        # sor 2: gombpárok
        c.gridy = row; c.gridx = 0
        rightContent.add(cookiePanel, c)
        c.gridx = 1
        rightContent.add(csrfPanel, c)
        row += 1


        # CSRF regex label + reset button (kept in the same style as other rows)
        c.gridy = row; c.gridx = 0; c.gridwidth = 1
        rightContent.add(swing.JLabel("Regex pattern (Python-style, first capturing group = token):"), c)
        self.resetCsrfRegexBtn = swing.JButton("Reset to default", actionPerformed=lambda e: self._on_reset_csrf_regex())
        c.gridx = 1
        rightContent.add(self.resetCsrfRegexBtn, c)
        row += 1

        # two-line text area for custom regex pattern
        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        self.csrfRegexArea = swing.JTextArea(self.csrf_default_pattern, 2, 40)
        self.csrfRegexArea.setLineWrap(False)
        self.csrfRegexArea.setToolTipText("Custom regex to extract the CSRF token. The first capturing group is used.")
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
        self.custom_codeblock_status = False
        c.gridx = 1
        rightContent.add(self.timeoutField, c)
        row += 1

        c.gridy = row; c.gridx = 0
        rightContent.add(swing.JLabel("Payload1 param name (p4yl04dm4rk3r):"), c)
        self.payloadParamField = swing.JTextField(self.payload_param_name, 10)
        c.gridx = 1
        rightContent.add(self.payloadParamField, c)
        row += 1

        # new attribute default
        self.payload_param2_name = "w"

        # UI: second payload param name field (next to payloadParamField)
        c.gridy = row; c.gridx = 0
        rightContent.add(swing.JLabel("Payload2 param name (53c0undm4rk3r):"), c)
        self.payloadParam2Field = swing.JTextField(self.payload_param2_name, 10)
        c.gridx = 1
        rightContent.add(self.payloadParam2Field, c)
        row += 1


        # custom code text area (multi-line)
        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        self.customCodeArea = swing.JTextArea(self.default_code_text, 10, 40)
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

        # initially disable custom controls (preserve original behavior)
        self._on_toggle_custom()

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
        row += 1  

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

    # --- Error/output area (isolated in its own container, expands only within itself) ---
    def _log(self, msg):
        try:
            self.customStatusArea.setText(str(msg))
        except Exception as e:
            print("customStatusArea_SETTEXT_ERROR:", e)


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
                m = re.match(r"^\s*array\('b'\s*,\s*\[([0-9,\s]+)\]\s*\)\s*$", s)
                if m:
                    nums = [int(x.strip()) for x in m.group(1).split(',') if x.strip()]
                    if nums:
                        return bytes(nums).decode("latin-1", "replace")
            except Exception:
                pass

            # fallback: if string contains bracketed numbers like [72, 84, ...], try that
            try:
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


    def _on_proxy_toggle(self):
        """
        Toggle the proxy-mode processing flag. When enabled, the extension will
        actively intercept proxy requests and run the processing flow.
        """
        try:
            self._proxy_mode_active = bool(self.proxyModeBtn.isSelected())

            # mutual exclusion: if proxy ON, force local OFF
            if self._proxy_mode_active:
                try:
                    self._update_autofollow_enabled_on_proxy()
                except:
                    pass
            else:
                try:
                    self._update_autofollow_enabled_on_proxy()
                except:
                    pass

            self._log("Proxy processing toggled: %s" % ("ON" if self._proxy_mode_active else "OFF"))
        except Exception as e:
            self._log("Error toggling proxy processing: %s" % str(e))


    def _update_autofollow_enabled_on_proxy(self):
        """
        Enable autoFollowRTChk only if proxy mode is active AND
        useCheckPageChk is selected.
        """
        if self._proxy_mode_active and self.useCheckPageChk.isSelected():
            self.autoFollowRTChk.setEnabled(True)
        else:
            self.autoFollowRTChk.setSelected(False)
            self.autoFollowRTChk.setEnabled(False)


    def _on_use_checkpage_toggle(self, event=None):
        self.useCheckPageTemplate = self.useCheckPageChk.isSelected()
        self._update_autofollow_enabled_on_proxy()


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
            view_row = self.table.getSelectedRow()
            if view_row < 0:
                return ""

            model_row = self.table.convertRowIndexToModel(view_row)

            if not (0 <= model_row < len(self.logTableModel.displayed)):
                return ""

            entry = self.logTableModel.displayed[model_row]
            msg = entry.messageInfo

            reqb = msg.getRequest()
            if not reqb:
                return ""

            return self.helpers.bytesToString(reqb)

        except Exception as e:
            print("_get_request_text_from_selected error:", e)
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
                self.set_status("Loaded request into Request Template")
                self.tabbed.setSelectedIndex(1)
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
                self.set_status("Loaded request into CheckPageTemplate")
                self.tabbed.setSelectedIndex(2)
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
            self.set_status("CheckPageTemplate cleared")
        except:
            pass


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
        """
        entry: LogEntry
        """
        try:
            method = entry.method or ""
            host = entry.host or ""
            path = entry.path or ""
            status = str(entry.status or "")
            body_len = entry.body_len
            msg = entry.messageInfo
        except:
            return True

        field_map = {
            "Host": host,
            "Method": method,
            "Path": path,
            "Status": status,
        }

        try:
            for fname, cfg in self.display_filters.items():
                if not cfg.get("active"):
                    continue

                mode = cfg.get("mode", "eq")
                vals = cfg.get("values", [])
                if not vals:
                    return False

                matched = False
                cell = str(field_map.get(fname, "")).strip()

                # --- BodyLen ---
                if fname == "BodyLen":
                    try:
                        if body_len == "" or body_len is None:
                            matched = False
                        else:
                            actual = int(body_len)
                            for v in vals:
                                try:
                                    if int(v) == actual:
                                        matched = True
                                        break
                                except:
                                    pass
                    except:
                        matched = False

                # --- ResponseContent ---
                elif fname == "ResponseContent":
                    try:
                        resp = msg.getResponse()
                        hay = ""
                        if resp:
                            hay = self.helpers.bytesToString(resp)
                        for v in vals:
                            if not v:
                                continue
                            try:
                                pat = Pattern.compile(v, Pattern.CASE_INSENSITIVE | Pattern.DOTALL)
                                if pat.matcher(hay).find():
                                    matched = True
                                    break
                            except:
                                pass
                    except:
                        matched = False

                # --- Path partial ---
                elif fname == "Path":
                    for v in vals:
                        if v and v in cell:
                            matched = True
                            break

                # --- Default exact ---
                else:
                    for v in vals:
                        if v and cell == v:
                            matched = True
                            break

                # --- apply mode ---
                if mode == "eq":
                    if not matched:
                        return False
                else:
                    if matched:
                        return False

            return True

        except:
            return True


    def _refresh_table_display(self):
        try:
            self.logTableModel.rebuild(self._row_matches_filters)
        except Exception as e:
            self.customStatusArea.append(
                "refresh error: %s\n" % e
            )



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
            pass

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
            pass


    def set_status(self, txt):
        try:
            self.statusLabel.setText(txt)
        except:
            pass

    def clear_log(self, evt=None):
        try:
            self.logStore.clear()
            self.logTableModel.clear()
            self._log("Log cleared OK!")
        except Exception as e:
            try:
                self._log("Log cleared ERROR: %s\n" % str(e))
            except:
                pass

        
    def clear_selected(self, evt=None):
        try:
            view_rows = self.table.getSelectedRows()
            if not view_rows:
                swing.JOptionPane.showMessageDialog(None, "No rows selected.")
                return

            # view -> model index
            model_rows = sorted(
                [self.table.convertRowIndexToModel(v) for v in view_rows],
                reverse=True
            )

            removed = 0

            for r in model_rows:
                try:
                    entry = self.logTableModel.displayed[r]
                    # törlés a LogStore-ból (objektum alapon!)
                    if entry in self.logStore.entries:
                        self.logStore.entries.remove(entry)
                        removed += 1
                except:
                    pass

            # tábla újraépítése (filterek megtartása)
            try:
                self.logTableModel.rebuild(self._row_matches_filters)
            except:
                self.logTableModel.rebuild()

            self._log("Cleared %d selected" % removed)

        except Exception as e:
            try:
                self._log("clear_selected error: %s\n" % str(e))
            except:
                pass


    def toggle_pause(self, evt=None):
        self.paused = bool(self.pauseBtn.isSelected())
        self.set_status("Paused" if self.paused else "Running")


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
            sorter = self.table.getRowSorter()
            if sorter:
                sorter.setSortKeys([RowSorter.SortKey(0, SortOrder.ASCENDING)])
        except Exception as e:
            try:
                self._log("sort_by_index_asc ERROR: %s\n" % str(e))
            except:
                pass


    def add_selected_to_sitemap(self, event=None):
        view_rows = self.table.getSelectedRows()
        if not view_rows:
            swing.JOptionPane.showMessageDialog(None, "No rows selected.")
            return

        count = 0

        for view_row in view_rows:
            try:
                model_row = self.table.convertRowIndexToModel(view_row)

                if not (0 <= model_row < len(self.logTableModel.displayed)):
                    continue

                entry = self.logTableModel.displayed[model_row]
                msg = entry.messageInfo

                self.callbacks_ref.addToSiteMap(msg)

                try:
                    url = self.helpers.analyzeRequest(msg).getUrl()
                    if url:
                        self.callbacks_ref.includeInScope(url)
                except:
                    pass

                count += 1

            except Exception as e:
                self._log("add_selected_to_sitemap ERROR: %s\n" % str(e))

        self._log("Added %d selected to Site map" % count)


    def on_table_select(self, event):
        row = self.table.getSelectedRow()
        if row < 0:
            return

        model_row = self.table.convertRowIndexToModel(row)
        try:
            entry = self.logTableModel.displayed[model_row]
            msg = entry.messageInfo
        except:
            return

        self.controller.setMessageInfo(msg)
        self.reqViewer.setMessage(msg.getRequest(), True)
        self.respViewer.setMessage(msg.getResponse(), False)


    # append_log_row (filter-aware)
    # append_log_row (LogStore-alapú, de UI-kompatibilis)
    def append_log_row(self, toolFlag, host, method, path,
                    status, total_length, messageInfo, isRequest):

        if self.paused:
            return

        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        body_len = ""
        try:
            if not isRequest and messageInfo.getResponse():
                ar = self.helpers.analyzeResponse(messageInfo.getResponse())
                body_len = len(messageInfo.getResponse()) - ar.getBodyOffset()
        except:
            pass

        entry = self.logStore.add(
            ts, host, method, path,
            status or "",
            total_length or "",
            body_len or "",
            messageInfo
        )

        show = True
        try:
            if hasattr(self, "_row_matches_filters"):
                show = self._row_matches_filters(entry)
        except:
            pass

        self.logTableModel.add_entry_top(entry, show)

        try:
            self.set_status("Logged: %s" % path)
        except:
            pass



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


    # COOKIE and CSRF HELPERS
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
            self.csrfManager.clear()
            self.customStatusArea.setText("CSRF_token cleared")
        except Exception as e:
            try:
                self.customStatusArea.setText("Error clearing CSRF: %s" % e)
            except:
                pass

    def _on_show_csrf(self, evt=None):
        try:
            txt = self.csrfManager.dump()
            # put into customStatusArea so user sees current jar
            self.customStatusArea.setText("CSRF_token:\n%s" % txt)
        except Exception as e:
            try:
                self.customStatusArea.setText("Error showing CSRF: %s" % e)
            except:
                pass

    def _on_reset_csrf_regex(self, evt=None):
        try:
            self.csrfRegexArea.setText(self.csrf_default_pattern)
            self.customStatusArea.setText("CSRF regex reset to default.")
        except Exception as e:
            try:
                self.customStatusArea.setText("Error resetting CSRF regex: %s" % e)
            except:
                pass


    # ---------------------------
    # Custom codeblock helpers
    # ---------------------------
    def _on_toggle_custom(self, evt=None):
        self.custom_codeblock_status = bool(self.useCustomChk.isSelected())
        for w in [self.customCodeArea, self.testCodeBtn, self.resetBtn, self.timeoutField]:
            try:
                w.setEnabled(self.custom_codeblock_status)
            except:
                pass
        # show brief status
        try:
            if self.custom_codeblock_status:
                self._log("Custom codeblock enabled")
            else:
                self._log("")
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
        try:
            default_code_text = getattr(self, "default_code_text", "")
            self.customCodeArea.setText(default_code_text)
        except:
            pass



    def run_user_code(self, incoming_payload1, timeout_ms=500, incoming_payload2=None, incoming_csrf=None):
        """
        Execute user's custom_codeblock and enforce that the function:
        def custom_codeblock(payload1, payload2, csrf_token)
        returns exactly three values in order: payload1, payload2, csrf_token

        Returns (ok, out_tuple_or_none, err_str)
        - ok: True on success
        - out_tuple_or_none: (payload1, payload2, csrf_token) tuple when ok True
        - err_str: error message when ok False
        """
        # determine user code text: use editor only when custom enabled, otherwise use default
        try:
            print("incoming_payload1:", incoming_payload1)
            print("incoming_payload2:", incoming_payload2)
            print("incoming_csrf:", incoming_csrf)
        except:
            pass

        if self.custom_codeblock_status:
            user_code_text = str(self.customCodeArea.getText())
        else:
            # use the default template stored in the class, if any
            user_code_text = getattr(self, "default_code_text", "")
        ns = {}
        try:
            _exec_in_namespace(user_code_text, ns)
        except Exception as e:
            return False, None, "Compilation error: %s\n%s" % (e, traceback.format_exc())

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
                    result['exc'] = str(e) + "\n" + traceback.format_exc()
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
        except:
            pass
        return ""


    def _update_cookies_and_csrf(self, response_bytes):
        if not response_bytes:
            return

        # --- COOKIE UPDATE ---
        if getattr(self, "autoUpdateCookies", False):
            try:
                text = self.callbacks.getHelpers().bytesToString(response_bytes)
                self.cookieManager.update_from_response(text)
            except Exception as e:
                print("[CookieUpdate] error:", e)

        # --- CSRF UPDATE ---
        if getattr(self, "autoUpdateCsrf", False):
            try:
                # 1) UI → CsrfManager
                try:
                    pattern = self.csrfRegexArea.getText().strip()
                    self.csrfManager.pattern_to_use = pattern
                except:
                    self.csrfManager.pattern_to_use = None

                # 2) extract token
                ok, new_token = self.csrfManager.update_from_response(response_bytes)

                # 3) status message
                if ok:
                    try:
                        self.customStatusArea.setText("CSRF token updated.")
                    except:
                        pass

            except Exception as e:
                print("[CSRFUpdate] ERROR:", e)


    def _follow_redirects_chain(self, initial_request_bytes, initial_response_bytes, initial_target_host, initial_target_port, initial_https, max_redirects=10):
        """
        V4: simple, robust redirect-follow implementation.

        Parameters:
        - initial_request_bytes: original sent request (bytes or Java byte[]-like iterable)
        - initial_response_bytes: first received response (bytes or Java byte[]-like)
        - initial_target_host/port/https: initial target
        - max_redirects: max number of redirects to follow

        Returns:
        - final response as Python bytes, or None if unsuccessful.
        """
        try:
            print("_follow_redirects_chain_ENTRY")
            # --- helper: converting Java-iterable/bytearray -> Python bytes
            def _to_pybytes(b):
                try:
                    if isinstance(b, (bytes, bytearray)):
                        return bytes(b)
                    out = bytearray()
                    for x in b:
                        try:
                            iv = int(x)
                        except Exception:
                            try:
                                iv = ord(x)
                            except Exception:
                                iv = 0
                        if iv < 0:
                            iv += 256
                        out.append(iv)
                    return bytes(out)
                except Exception:
                    try:
                        return str(b).encode("latin-1", "replace")
                    except:
                        return b""

            # --- helper: extract standard text from response (string)
            def _response_to_text(resp_bytes):
                if resp_bytes is None:
                    return ""
                try:
                    if hasattr(self.helpers, "bytesToString"):
                        try:
                            return self.helpers.bytesToString(resp_bytes)
                        except:
                            pass
                    # fallback
                    pb = _to_pybytes(resp_bytes)
                    return pb.decode("latin-1", "replace")
                except:
                    try:
                        return str(resp_bytes)
                    except:
                        return ""

            # --- helper: extract status and Location headers
            def _extract_status_and_location(resp_bytes):
                txt = _response_to_text(resp_bytes)
                status = None
                loc = None
                try:
                    first_line = txt.split("\r\n", 1)[0]
                    parts = first_line.split()
                    if len(parts) >= 2:
                        try:
                            status = int(parts[1])
                        except:
                            status = None
                except:
                    status = None
                try:
                    hdrs = txt.split("\r\n\r\n", 1)[0].split("\r\n")[1:]
                    for h in hdrs:
                        if h.lower().startswith("location:"):
                            loc = h.split(":", 1)[1].strip()
                            break
                except:
                    loc = None
                return status, loc

            # --- initial states ---
            steps = 0
            current_resp = initial_response_bytes
            current_req = initial_request_bytes
            current_host = initial_target_host
            current_port = initial_target_port
            current_https = bool(initial_https)
            print("current_host:", current_host)
            print("current_port:", current_port)
            print("current_https:", current_https)

            while steps < int(max_redirects):
                steps += 1

                status, location = _extract_status_and_location(current_resp)
                print("status:", status)
                print("location:", location)

                # update cookie and csrf from the response just received (if enabled)
                self._update_cookies_and_csrf(current_resp)
                print("Cookie and CSRF updated if enabled")
                # if there is no redirect status or no Location -> return the current response
                try:
                    if status is None or not (300 <= int(status) < 400) or not location:
                        return _to_pybytes(current_resp)
                except:
                    return _to_pybytes(current_resp)

                # --- Resolve new absolute URL from Location (relative or absolute) ---
                new_url = None
                try:
                    # ha location abszolút -> használjuk
                    loc_l = location.strip()
                    if loc_l.lower().startswith("http://") or loc_l.lower().startswith("https://"):
                        new_url = loc_l
                    else:
                        # try to extract base url from current_req (analyzeRequest)
                        base = None
                        try:
                            if current_req:
                                try:
                                    parsed_req = None
                                    if hasattr(self.helpers, "analyzeRequest"):
                                        try:
                                            parsed_req = self.helpers.analyzeRequest(current_req)
                                            uobj = parsed_req.getUrl()
                                            if uobj:
                                                proto = uobj.getProtocol()
                                                hostb = uobj.getHost()
                                                portb = uobj.getPort()
                                                pathb = uobj.getPath() or "/"
                                                q = uobj.getQuery()
                                                if q:
                                                    pathb = pathb + "?" + q
                                                if not portb or int(portb) <= 0:
                                                    portb = (443 if str(proto).lower()=="https" else 80)
                                                base = "%s://%s%s" % (str(proto).lower(), hostb, ((":%d" % portb) if ((str(proto).lower()=="https" and portb!=443) or (str(proto).lower()=="http" and portb!=80)) else ""))
                                                base = base + pathb
                                        except:
                                            parsed_req = None
                                except:
                                    current_req = None
                        except:
                            base = None

                        if base and urljoin is not None:
                            try:
                                new_url = urljoin(base, loc_l)
                            except:
                                new_url = None
                        else:
                            # fallback: use current_host/current_port
                            scheme = "https" if current_https else "http"
                            if current_host:
                                if loc_l.startswith("/"):
                                    new_url = "%s://%s%s" % (scheme, current_host, loc_l)
                                else:
                                    new_url = "%s://%s/%s" % (scheme, current_host, loc_l)
                except Exception as e:
                    print("[Resolve new absolute URL from Location] ERROR: %s" % str(e))
                    new_url = None

                if not new_url:
                    return _to_pybytes(current_resp)

                # --- build new request for new_url (GET, no body) ---
                try:
                    # parse new_url
                    p = urlparse(new_url) if urlparse is not None else None
                    scheme = p.scheme if p and getattr(p, "scheme", None) else ("https" if current_https else "http")
                    new_host = p.hostname if p else current_host
                    new_port = p.port if p and getattr(p, "port", None) else (443 if scheme == "https" else 80)
                    new_path = (p.path or "/") + (("?" + p.query) if p and getattr(p, "query", None) else "")
                except:
                    new_host = current_host
                    new_port = current_port
                    scheme = "https" if current_https else "http"
                    new_path = "/"

                # build minimal GET headers preserving User-Agent if possible
                headers = ["GET %s HTTP/1.1" % new_path, "Host: %s%s" % (new_host, ((":%d" % new_port) if ((scheme=="https" and new_port!=443) or (scheme=="http" and new_port!=80)) else "")), "Connection: close"]
                try:
                    # try copy User-Agent from previous request if available
                    try:
                        if current_req and hasattr(self.helpers, "analyzeRequest"):
                            pr = self.helpers.analyzeRequest(current_req)
                            for h in pr.getHeaders():
                                hs = str(h)
                                if hs.lower().startswith("user-agent:"):
                                    headers.append(hs)
                                    break
                    except:
                        pass
                except Exception as e:
                    print("[build minimal GET headers preserving User-Agent if possible] ERROR: %s" % str(e))
                    pass

                # build bytes via helpers if available
                try:
                    if hasattr(self.helpers, "buildHttpMessage"):
                        try:
                            new_req_bytes = self.helpers.buildHttpMessage(headers, b"")
                        except:
                            # fallback to stringToBytes
                            try:
                                txt = "\r\n".join(headers) + "\r\n\r\n"
                                if hasattr(self.helpers, "stringToBytes"):
                                    new_req_bytes = self.helpers.stringToBytes(txt)
                                else:
                                    new_req_bytes = txt.encode("latin-1", "replace")
                            except:
                                new_req_bytes = None
                    else:
                        txt = "\r\n".join(headers) + "\r\n\r\n"
                        new_req_bytes = txt.encode("latin-1", "replace")
                except Exception as e:
                    print("[build bytes via helpers if available] ERROR: %s" % str(e))
                    new_req_bytes = None

                if not new_req_bytes or not new_host:
                    return _to_pybytes(current_resp)

                # inject cookies into the new request if cookie auto-update is enabled
                try:
                    if getattr(self, "autoUpdateCookies", False) and getattr(self, "cookieManager", None):
                        try:
                            txt_req = self.helpers.bytesToString(new_req_bytes) if hasattr(self.helpers, "bytesToString") else _to_pybytes(new_req_bytes).decode("latin-1", "replace")
                            injected = self.cookieManager.inject_into_request(txt_req)
                            if injected is not None:
                                try:
                                    new_req_bytes = self.helpers.stringToBytes(injected)
                                except:
                                    new_req_bytes = injected.encode("latin-1", "replace")
                        except:
                            pass
                except Exception as e:
                    print("[inject cookies into the new request if cookie auto-update is enabled] ERROR: %s" % str(e))
                    pass

                # send via Burp callbacks
                try:
                    # prefer buildHttpService + makeHttpRequest
                    try:
                        svc = self.helpers.buildHttpService(new_host, int(new_port), "https" if scheme.lower()=="https" else "http")
                        resp_obj = self.callbacks.makeHttpRequest(svc, new_req_bytes)
                    except Exception:
                        resp_obj = None
                        try:
                            resp_obj = self.callbacks.makeHttpRequest(new_host, int(new_port), bool(scheme.lower()=="https"), new_req_bytes)
                        except:
                            resp_obj = None

                    if not resp_obj:
                        return _to_pybytes(current_resp)

                    # poll for response bytes
                    new_resp = None
                    attempts = 20
                    for _ in range(attempts):
                        try:
                            new_resp = resp_obj.getResponse()
                        except:
                            new_resp = None
                        if new_resp:
                            break
                        time.sleep(0.08)

                    if not new_resp:
                        return _to_pybytes(current_resp)

                    # update loop state and continue
                    current_resp = new_resp
                    current_req = new_req_bytes
                    current_host = new_host
                    current_port = new_port
                    current_https = (scheme.lower() == "https")
                    continue

                except Exception as e:
                    print("[prefer buildHttpService + makeHttpRequest] ERROR: %s" % str(e))
                    return _to_pybytes(current_resp)

            # exceeded max redirects -> return current_resp
            return _to_pybytes(current_resp)

        except Exception as e:
            print("[helper: converting Java-iterable/bytearray -> Python bytes] ERROR: %s" % str(e))
            try:
                return _to_pybytes(initial_response_bytes)
            except:
                return None



    def build_request_from_template(
        self,
        get_editor_message=None,
        helpers=None,
        cookie_manager=None,
        csrf_manager=None,
        auto_update_cookies=False,
        auto_update_csrf=False,
        normalize_func=None,
        custom_status_setter=None,
        incoming_payload1="",
        incoming_payload2="",
        fallback_resp=None
    ):
        """
        Clean, robust template -> request builder.
        Returns:
        (request_bytes, forced_https_flag, final_request_text)
        or on error:
        (fallback_resp)
        """

        try:
            # 1) load template text (editor preferred, textarea fallback)
            template_text = ""
            try:
                if callable(get_editor_message):
                    tb = get_editor_message()
                    if tb is None:
                        template_text = ""
                    else:
                        # helpers.bytesToString if available
                        if helpers is not None:
                            try:
                                template_text = helpers.bytesToString(tb)
                            except Exception:
                                # tb lehet bytes/object
                                try:
                                    if isinstance(tb, (bytes, bytearray)):
                                        template_text = tb.decode("latin-1", "replace")
                                    else:
                                        template_text = str(tb)
                                except:
                                    template_text = str(tb)
                        else:
                            try:
                                if isinstance(tb, (bytes, bytearray)):
                                    template_text = tb.decode("latin-1", "replace")
                                else:
                                    template_text = str(tb)
                            except:
                                template_text = str(tb)
            except Exception:
                template_text = ""

            payload_marker = "p4yl04dm4rk3r"
            payload_marker2 = "53c0undm4rk3r"
            csrf_marker = "c5rfm4rk3r"

            if not template_text or not template_text.strip():
                self._log("No Request Template configured; Incoming request forwarded.")
                print("RETURN: template empty")
                return (fallback_resp)


            # --- CSRF token to pass to user-code (do not auto-update here) ---
            csrf_token = None
            try:
                csrf_token = csrf_manager.get_token()
                print("[CSRF token to pass to user-code] OK: %s" % csrf_token)
            except Exception as e:
                print("[CSRF token to pass to user-code] ERROR: %s" % e)


            # 1,5) load template text (editor preferred, textarea fallback)
            if self.custom_codeblock_status and (incoming_payload1 or incoming_payload2):
                # --- run user code (contract: returns tuple(payload1,payload2,csrf) ) ---
                try:
                    try:
                        t_ms = int(self.timeoutField.getText())
                    except Exception as e:
                        print("[Timeout field reading] ERROR: %s" % e)
                        try:
                            t_ms = self.custom_timeout_ms
                            print("[Default timeout value reading] OK: %s" % t_ms)
                        except Exception as e:                           
                            print("[Default timeout value reading] ERROR: %s" % e)

                    if csrf_token is not None:
                        ok, out, err = self.run_user_code(incoming_payload1, t_ms, incoming_payload2, csrf_token)
                        print("[run_user_code] OK")
                    else:
                        ok, out, err = self.run_user_code(incoming_payload1, t_ms, incoming_payload2, None)
                        print("[run_user_code] OK")
                except Exception as e:
                    ok = False
                    out = None
                    err = "user code exception"
                    print("[run_user_code] ERROR: %s" % e)

                if ok and out is not None and isinstance(out, (list, tuple)):
                    if len(out) == 3:
                        outgoing_payload1 = out[0] or ""
                        outgoing_payload2 = out[1] or ""
                        csrf_token = out[2]
                    elif len(out) == 2:
                        outgoing_payload1 = out[0] or ""
                        outgoing_payload2 = out[1] or ""
                        csrf_token = csrf_token
            else:            
                outgoing_payload1 = incoming_payload1
                outgoing_payload2 = incoming_payload2
                csrf_token = csrf_token


            # 2) Replace payload markers (safe replace even if missing)
            try:
                final_request_text = template_text.replace(payload_marker, outgoing_payload1 or "")
                final_request_text = final_request_text.replace(payload_marker2, outgoing_payload2 or "")
                print("[Replace payload markers] OK, length: %d" % len(final_request_text))
            except Exception as e:
                print("[Replace payload markers] ERROR: %s" % str(e))
                return (fallback_resp)

            # 3) Cookie injection (if enabled)
            try:
                if auto_update_cookies and cookie_manager is not None:
                    try:
                        injected = cookie_manager.inject_into_request(final_request_text)
                        if injected is not None:
                            # inject_into_request returns str
                            final_request_text = injected if isinstance(injected, str) else (injected.decode("latin-1", "replace") if isinstance(injected, (bytes, bytearray)) else str(injected))
                        print("CookieManager: injected cookies -> final_request length: %d" % len(final_request_text))
                    except Exception as e:
                        print("CookieManager inject error: %s" % str(e))
                else:
                    # diagnostic, if cookie_manager present but injection disabled, we do nothing
                    pass
            except Exception:
                pass

            # 4) CSRF injection (if enabled)
            try:
                if auto_update_csrf and csrf_manager is not None:
                    try:
                        token_val = csrf_token
                        if token_val is not None:
                            try:
                                final_request_text = final_request_text.replace(csrf_marker, token_val)
                                print("CsrfManager: injected token for %s" % (token_val))
                            except Exception as e:
                                print("CsrfManager inject error: %s" % str(e))
                        else:
                            print("CsrfManager: no cached token!")
                    except Exception as e:
                        print("Csrf injection outer error: %s" % str(e))
            except Exception:
                pass


            # 6) normalization hook
            try:
                if callable(normalize_func):
                    final_request_text = normalize_func(final_request_text)
            except Exception:
                pass

            # 7) build request bytes (helpers preferred)
            try:
                if helpers is not None:
                    try:
                        request_bytes = helpers.stringToBytes(final_request_text)
                    except Exception:
                        request_bytes = final_request_text.encode("latin-1", "replace")
                else:
                    request_bytes = final_request_text.encode("latin-1", "replace")
            except Exception:
                request_bytes = final_request_text.encode("latin-1", "replace")

            # 8) parse headers/body: prefer helpers.analyzeRequest, fallback simple split
            headers = []
            body_bytes = b""
            try:
                parsed_req = None
                if helpers is not None:
                    try:
                        parsed_req = helpers.analyzeRequest(request_bytes)
                    except Exception:
                        parsed_req = None

                if parsed_req:
                    try:
                        headers = list(parsed_req.getHeaders())
                        bo = parsed_req.getBodyOffset()
                        body_bytes = request_bytes[bo:]
                    except Exception:
                        headers = []
                        body_bytes = b""
                else:
                    # simple split
                    try:
                        s = request_bytes if isinstance(request_bytes, (bytes, bytearray)) else (request_bytes.encode("latin-1", "replace"))
                        sep = b"\r\n\r\n"
                        idx = s.find(sep)
                        if idx >= 0:
                            hdrs_block = s[:idx].decode("latin-1", "replace").split("\r\n")
                            headers = hdrs_block
                            body_bytes = s[idx+4:]
                        else:
                            headers = []
                            body_bytes = b""
                    except Exception:
                        headers = []
                        body_bytes = b""
            except Exception:
                headers = []
                body_bytes = b""

            # 9) ensure Content-Length is correct (if body present)
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
                except Exception:
                    try:
                        new_headers.append(str(h))
                    except Exception:
                        pass
            if not cl_handled and len(body_bytes) > 0:
                new_headers.append("Content-Length: %d" % len(body_bytes))

            # 10) try to rebuild http message via helpers.buildHttpMessage
            try:
                if helpers is not None:
                    try:
                        request_bytes = helpers.buildHttpMessage(new_headers, body_bytes)
                    except Exception:
                        # leave request_bytes as-is if rebuild fails
                        pass
                else:
                    # no helpers: keep request_bytes as-is (already bytes)
                    pass
            except Exception:
                pass

            # success: return
            return (request_bytes)

        except Exception as e:
            try:
                print("build_request_from_template: unexpected error: %s" % str(e))
            except Exception:
                pass
            return (fallback_resp)


    def proxy_flow_process_request(self, raw_request_bytes, orig_host, orig_port, orig_https):
        """
        Main proxy-side mini-workflow.
        Input: raw_request_bytes from intercepted proxy message.
        Returns: (final_request_bytes, target_host, target_port, target_https, final_request_text, fallback_resp)
        If something fails or no payload found -> returns (None, None, None, None, None, fallback_resp)
        """
        # fallback response (kept for compatibility though proxy branch returns bytes only)
        fallback_resp = None

        try:
            if not raw_request_bytes:
                return (None)

            # decode safely for parsing
            try:
                req_text = self._to_text(raw_request_bytes)
            except:
                try:
                    req_text = raw_request_bytes.decode("latin-1", "replace")
                except:
                    req_text = str(raw_request_bytes)

            # --- extract payload param names ---
            try:
                pname1 = str(self.payloadParamField.getText()).strip()
            except:
                pname1 = getattr(self, "payload_param_name", "q")
            try:
                pname2 = str(self.payloadParam2Field.getText()).strip()
            except:
                pname2 = getattr(self, "payload_param2_name", "w")

            # --- extract incoming payloads from query/body (robust) ---
            incoming_payload1 = ""
            incoming_payload2 = ""
            try:
                # prefer HTTP/2 pseudo :path if present
                first_line = req_text.split("\r\n", 1)[0]
                parts = first_line.split()
                path = parts[1] if len(parts) >= 2 else "/"
                # parse query string
                if "?" in path:
                    qstr = path.split("?", 1)[1]
                    for kv in qstr.split("&"):
                        if "=" in kv:
                            k, v = kv.split("=", 1)
                            if k == pname1 and not incoming_payload1:
                                incoming_payload1 = v
                            elif k == pname2 and not incoming_payload2:
                                incoming_payload2 = v
                # fallback: also check body if present
                hdr_body = req_text.split("\r\n\r\n", 1)
                body_text = hdr_body[1] if len(hdr_body) > 1 else ""
                # form-urlencoded detection
                if body_text and ("=" in body_text) and ("application/x-www-form-urlencoded" in req_text.lower()):
                    for kv in body_text.split("&"):
                        if "=" in kv:
                            k, v = kv.split("=", 1)
                            if k == pname1 and not incoming_payload1:
                                incoming_payload1 = v
                            elif k == pname2 and not incoming_payload2:
                                incoming_payload2 = v
            except Exception:
                pass

            incoming_payload1 = incoming_payload1 or ""
            incoming_payload2 = incoming_payload2 or ""


            # --- If no payloads at all, do not interfere (let proxy forward original) ---
            if not incoming_payload1 and not incoming_payload2:
                return (None)


            # --- Build Request Template request bytes (do not send it yet) ---
            try:
                request_bytes = self.build_request_from_template(
                    get_editor_message=lambda: self.reqTemplateEditor.getMessage() if hasattr(self, "reqTemplateEditor") else None,
                    helpers=self.helpers,
                    cookie_manager=self.cookieManager,
                    csrf_manager=self.csrfManager,
                    auto_update_cookies=getattr(self, "autoUpdateCookies", False),
                    auto_update_csrf=getattr(self, "autoUpdateCsrf", False),
                    normalize_func=None,
                    custom_status_setter=lambda s: None,
                    incoming_payload1=incoming_payload1,
                    incoming_payload2=incoming_payload2,
                    fallback_resp=fallback_resp
                )
            except Exception as e:
                try:
                    print("proxy_flow_process_request: request template build failed:", e)
                except:
                    pass
                return (None)

            if not request_bytes:
                return (None)


            # If CheckPage NOT used: return the request template as final
            try:
                use_cpt = bool(getattr(self, "useCheckPageTemplate", False)) or bool(getattr(self, "checkPageTemplateCheckbox", False) and self.checkPageTemplateCheckbox.isSelected())
            except:
                use_cpt = False

            if not use_cpt:
                return (request_bytes)

            target_host = orig_host
            target_port = orig_port
            target_https = orig_https

            # --- ELSE: CheckPage is used -> we must run the small internal flow:
            # 1) send the Request Template (so we can update cookies/csrf and follow redirects if requested)
            # 2) build the CheckPage request using updated state
            resp_obj = None
            try:
                # build service & send (prefer buildHttpService + makeHttpRequest)
                try:
                    svc = self.helpers.buildHttpService(target_host, int(target_port), "https" if target_https else "http")
                    # mark_request_as_workflow_generated is not required in the new flow
                    resp_obj = self.callbacks.makeHttpRequest(svc, request_bytes)
                except Exception:
                    # fallback older API
                    try:
                        resp_obj = self.callbacks.makeHttpRequest(target_host, int(target_port), bool(target_https), request_bytes)
                    except Exception as e:
                        resp_obj = None
                        try:
                            print("proxy_flow_process_request: makeHttpRequest failed:", e)
                        except:
                            pass

                # poll for response bytes
                response_bytes = None
                if resp_obj:
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
            except Exception as e:
                try:
                    print("proxy_flow_process_request: sending request-template failed:", e)
                except:
                    pass
                response_bytes = None

            # If we couldn't get response, we still can attempt to build CheckPage (best-effort) OR abort
            if response_bytes:
                # update cookie manager / csrf from response if options enabled
                self._update_cookies_and_csrf(response_bytes)

                # optionally follow redirects for request template if user requested it (allowed when CheckPage active)
                try:
                    if self.autoFollowRTChk.isEnabled():
                        print("autoFollowRTChk:", self.autoFollowRTChk.isEnabled())
                        # attempt to follow redirect chain using helper (reuse existing logic if present)
                        try:
                            final_bytes = self._follow_redirects_chain(request_bytes, response_bytes, target_host, target_port, target_https, max_redirects=10)
                            if final_bytes:
                                response_bytes = final_bytes
                        except:
                            pass
                except:
                    pass

            # --- Build CheckPage request now, using updated cookie/csrf state and outgoing payloads ---
            try:
                cp_bytes = self.build_checkpage_request(incoming_payload1=incoming_payload1, incoming_payload2=incoming_payload2)
            except Exception as e:
                try:
                    print("proxy_flow_process_request: build_checkpage_request failed:", e)
                except:
                    pass
                cp_bytes = None

            if not cp_bytes:
                # fallback -> use the request template
                return (request_bytes)

            # success: return the CheckPage request as the final request to give to the proxy
            return (cp_bytes)

        except Exception as e:
            try:
                print("proxy_flow_process_request top-level exception:", e)
            except:
                pass
            return (None)

    def build_checkpage_request(self, incoming_payload1="", incoming_payload2=""):
        """
        Build CheckPage request bytes from the CheckPage editor/template.
        Returns (request_bytes, forced_https_flag, final_request_text) or (None,None,None) on failure.
        """
        try:
            # get editor content
            try:
                editor_msg = self.checkPageEditor.getMessage() if hasattr(self, "checkPageEditor") else None
            except:
                editor_msg = None

            # call existing template builder (keeps behavior consistent)
            try:
                request_bytes = self.build_request_from_template(
                    get_editor_message=lambda: editor_msg,
                    helpers=self.helpers,
                    cookie_manager=self.cookieManager,
                    csrf_manager=self.csrfManager,
                    auto_update_cookies=getattr(self, "autoUpdateCookies", False),
                    auto_update_csrf=getattr(self, "autoUpdateCsrf", False),
                    normalize_func=None,
                    custom_status_setter=lambda s: None,
                    incoming_payload1=incoming_payload1 or "",
                    incoming_payload2=incoming_payload2 or "",                 
                    fallback_resp=None
                )
            except Exception as e:
                try:
                    print("build_checkpage_request: build_request_from_template error:", e)
                except:
                    pass
                return (None)

            if not request_bytes:
                return (None)

            return (request_bytes)

        except Exception as e:
            try:
                print("build_checkpage_request top-level exception:", e)
            except:
                pass
            return (None)



class BurpExtender(IBurpExtender, IHttpListener, IProxyListener):
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

        # register proxy listener so we can intercept proxy messages when Proxy Mode ON
        try:
            callbacks.registerProxyListener(self)
        except Exception as e:
            print("registerProxyListener failed (ignored):", e)

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
                    except Exception as e:
                        print("append invoke error:", e)
                swing.SwingUtilities.invokeLater(_append)
        except Exception as e:
            print("processHttpMessage error:", e)


    def processProxyMessage(self, messageIsRequest, interceptedMessage):
        """
        Proxy listener: single-entry request-branch implementation.
        Build the final request (RequestTemplate or CheckPage) synchronously,
        then replace the proxied request and let Burp forward it.
        """
        try:
            # ====================================================
            # RESPONSE BRANCH – update cookie / csrf from server
            # ====================================================
            if not messageIsRequest:

                # extract response
                # ---------------------------------------------------------------
                # UNIFIED COOKIE + CSRF UPDATE BLOCK (FINAL VERSION)
                # ---------------------------------------------------------------

                try:
                    msg_info = interceptedMessage.getMessageInfo()
                    if not msg_info:
                        interceptedMessage.setInterceptAction(interceptedMessage.ACTION_DONT_INTERCEPT)
                        return

                    resp_bytes = msg_info.getResponse()
                    if not resp_bytes:
                        interceptedMessage.setInterceptAction(interceptedMessage.ACTION_DONT_INTERCEPT)
                        return
                except:
                    interceptedMessage.setInterceptAction(interceptedMessage.ACTION_DONT_INTERCEPT)
                    return
                # update cookie manager / csrf from response if options enabled
                self.ui._update_cookies_and_csrf(resp_bytes)

                # proxy continue on its way
                interceptedMessage.setInterceptAction(interceptedMessage.ACTION_DONT_INTERCEPT)
                return


            # UI readiness + proxy mode enabled?
            try:
                if not getattr(self, "ui", None):
                    return
                if not getattr(self.ui, "_proxy_mode_active", False):
                    return
            except:
                return

            # get message info and raw request bytes and service
            try:
                msg_info = interceptedMessage.getMessageInfo()
                if not msg_info:
                    return
                raw_req = msg_info.getRequest()
                if not raw_req:
                    return
                service = msg_info.getHttpService()
                if not service:
                    return
            except:
                return

            # get orig_hos, torig_port, orig_https            
            orig_host  = service.getHost()
            orig_port  = service.getPort()
            orig_https = (service.getProtocol().lower() == "https")


            # run the unified proxy-workflow on this raw request (implemented on UI)
            try:
                final_req = self.ui.proxy_flow_process_request(raw_req, orig_host, orig_port, orig_https)
            except Exception as e:
                # on any internal error, let Burp forward the original request
                try:
                    interceptedMessage.setInterceptAction(interceptedMessage.ACTION_DONT_INTERCEPT)
                except:
                    pass
                try:
                    print("processProxyMessage: proxy_flow_process_request exception:", e)
                except:
                    pass
                return

            # If the workflow decided not to replace the request, let it pass unchanged
            if not final_req:
                try:
                    interceptedMessage.setInterceptAction(interceptedMessage.ACTION_DONT_INTERCEPT)
                except:
                    pass
                return

            # Replace the proxy's request with our final request and let Burp forward it
            try:
                msg_info.setRequest(final_req)
                interceptedMessage.setInterceptAction(interceptedMessage.ACTION_DONT_INTERCEPT)
            except Exception as e:
                try:
                    interceptedMessage.setInterceptAction(interceptedMessage.ACTION_DONT_INTERCEPT)
                except:
                    pass
                try:
                    print("processProxyMessage: setRequest/setAction failed:", e)
                except:
                    pass
            return

        except Exception as e:
            try:
                print("processProxyMessage outer exception:", e)
            except:
                pass
