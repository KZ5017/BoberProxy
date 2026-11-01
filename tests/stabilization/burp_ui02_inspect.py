# -*- coding: utf-8 -*-
"""Finite public Swing inspection of native Proxy settings controls; no clicks."""
from burp import IBurpExtender
from javax.swing import AbstractButton, JMenuItem, JLabel, JTable, JTree, SwingUtilities
from javax.swing.text import JTextComponent
from java.awt import Container, Frame
from java.lang import Throwable
import json
import os
import re
import traceback


def inspect_controls(roots):
    report = dict(kind='UI02-native-proxy-settings-button-inspection', controls=[], visited=0)
    pending = list(roots)
    while pending and report['visited'] < 20000:
        component = pending.pop()
        report['visited'] += 1
        if isinstance(component, (AbstractButton, JLabel)):
            text = re.sub(r'<[^>]+>', '', unicode(component.getText() or '')).strip().lower()
            if text == 'proxy settings' and component.getName() != 'BoberProxy.proxySettings':
                icon = component.getIcon()
                is_button = isinstance(component, AbstractButton) and not isinstance(component, JMenuItem)
                report['controls'].append(dict(
                    component_class=str(type(component)),
                    actionable=bool(is_button), showing=bool(component.isShowing()),
                    enabled=bool(component.isEnabled()),
                    icon_size=[int(icon.getIconWidth()), int(icon.getIconHeight())] if icon else None,
                    action_present=bool(is_button and component.getAction() is not None),
                    listeners=len(component.getActionListeners()) if is_button else None,
                    font_size=float(component.getFont().getSize2D())))
        if isinstance(component, Container) and not isinstance(component, (JTextComponent, JTable, JTree)):
            pending.extend(list(component.getComponents()))
    report['bounded_scan_complete'] = not pending
    return report


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName('BoberProxy UI02 native button inspection')
        report = {}
        def inspect():
            report.update(inspect_controls(Frame.getFrames()))
        try:
            if SwingUtilities.isEventDispatchThread():
                inspect()
            else:
                SwingUtilities.invokeAndWait(inspect)
            report['burp_version'] = list(callbacks.getBurpVersion())
            directory = os.path.dirname(str(callbacks.getExtensionFilename()))
            path = os.path.join(directory, 'runtime', 'ui02-native-button.json')
            with open(path, 'w') as handle:
                json.dump(report, handle, indent=2)
            count = sum(1 for control in report['controls'] if control['actionable'])
            callbacks.printOutput('UI02_PROXY_BUTTON FOUND (%d actionable controls)\n%s' % (count, path))
        except (BaseException, Throwable):
            callbacks.printError(traceback.format_exc())
