"""Validated, explicit detection-mode switch (I vs. M) on the real orchestrator.

Toggles the DETECTION_CROSS_DOMAIN_CORRELATION setting that already exists
in orchestrator-ddos-pucp's config/settings.py -- an orthogonal correlation
flag that only changes whether telemetry is merged across domains before
the detector sees it; the detection, decision and mitigation code paths
themselves are identical either way. This module adds no new behaviour to
that flag: it only automates toggling it the same way ThresholdControl
(threshold_control.py) automates threshold edits -- same guard, same lock,
same remote-execution helper already used elsewhere in this codebase.

    I (isolated)    -> flag off
    M (multidomain) -> flag on

Writing this file does not run anything by itself: it is only created
here, not executed. Any call to DetectionModeControl.apply() against the
real orchestrator is a separate, explicit action requiring its own
confirmation, same as threshold_control.py's apply().
"""
import json
from .baseline import BaselineGuard

MODES = {'isolated': 'false', 'multidomain': 'true'}

_READ_CODE = """import re,subprocess,json
out=subprocess.run(['systemctl','show','ryu-manager','-p','Environment'],capture_output=True,text=True,check=True).stdout
m=re.search(r'DETECTION_CROSS_DOMAIN_CORRELATION=(true|false)',out)
print(json.dumps(dict(override={'true':'multidomain','false':'isolated'}.get(m.group(1)) if m else None)))
"""

_APPLY_TEMPLATE = """import json,os,re,socket,subprocess,time
from pathlib import Path
mode={mode!r};value={value!r}
lease=Path('/run/benign-baseline/lease.json')
if lease.exists() and json.loads(lease.read_text()).get('expires_at',0)>time.time():
    raise RuntimeError('A baseline lease is active')
log_path=Path('/var/log/ryu-manager.log')
offset=log_path.stat().st_size if log_path.exists() else 0
dropin_dir=Path('/run/systemd/system/ryu-manager.service.d')
dropin=dropin_dir/'99-detection-mode.conf'
dropin_dir.mkdir(parents=True,exist_ok=True)
dropin.write_text('[Service]' + chr(10) + 'Environment=DETECTION_CROSS_DOMAIN_CORRELATION=' + value + chr(10))
subprocess.run(['systemctl','daemon-reload'],check=True,timeout=20)
subprocess.run(['systemctl','restart','ryu-manager'],check=True,timeout=20)
deadline=time.monotonic()+60;observed=None
while time.monotonic()<deadline:
    time.sleep(1)
    try:
        socket.create_connection(('127.0.0.1',6653),1).close()
    except OSError:
        continue
    with open(log_path,'rb') as f:
        f.seek(offset);log=f.read().decode(errors='replace')
    m=re.search(r'DETECTION_MODE=(\\w+)',log)
    if m:
        observed=m.group(1);break
if observed!=mode:
    dropin.unlink(missing_ok=True)
    subprocess.run(['systemctl','daemon-reload'],timeout=20)
    subprocess.run(['systemctl','restart','ryu-manager'],timeout=20)
    raise RuntimeError('ryu-manager restarted but reported DETECTION_MODE=' + str(observed) + ', expected ' + mode + ' -- reverted and restored previous mode')
print(json.dumps(dict(applied=mode,controller_restarted=True)))
"""


class DetectionModeControl:
    """Mirrors ThresholdControl's shape exactly (same BaselineGuard, same
    SSH call signature) so callers that already know one already know
    the other."""

    def __init__(self, cfg):
        self.guard = BaselineGuard(cfg, 'detection-mode-control', 0)

    async def read(self):
        return json.loads(await self.guard.controller(_READ_CODE))

    async def apply(self, mode):
        if mode not in MODES:
            raise ValueError('Unsupported detection mode: ' + repr(mode))
        code = _APPLY_TEMPLATE.format(mode=mode, value=MODES[mode])
        return json.loads(await self.guard.ssh(
            self.guard.control['host'], self.guard.control['user'],
            'python3 -', root=True, payload=code, timeout=90))
