# -*- coding: utf-8 -*-
"""Disposable JVM only: larger private widget fonts, no UIManager mutations."""
import json,sys
from javax.swing import SwingUtilities
from javax import swing
import probe_target_scope_native as probe

original=probe.load_source
class PrivateSwing(object):
    def __init__(self):
        self.types={}
        for name in ('JButton','JToggleButton','JCheckBox','JLabel','JTextField','JComboBox'):
            base=getattr(swing,name)
            def factory(base):
                class Scaled(base):
                    def __init__(self,*args,**kwargs):
                        base.__init__(self,*args,**kwargs)
                        font=self.getFont()
                        self.setFont(font.deriveFont(float(font.getSize2D())*1.35))
                return Scaled
            self.types[name]=factory(base)
    def __getattr__(self,name): return self.types.get(name,getattr(swing,name))
def load(path):
    ns,raw=original(path)
    ns['swing']=PrivateSwing()
    return ns,raw
probe.load_source=load
report=probe.run_checks()
report.update(kind='TG04-standalone-private-widgets-font135-no-global-UIManager',font_scale=1.35)
with open(sys.argv[1],'w') as f:json.dump(report,f,indent=2,ensure_ascii=True)
print('TG_SCOPE_LARGE_FONT '+('PASS' if report['passed'] else 'FAIL')+' (%d checks)'%len(report['checks']))
sys.exit(0 if report['passed'] else 1)
