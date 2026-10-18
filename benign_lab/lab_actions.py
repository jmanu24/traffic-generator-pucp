"""Actions on the distributed lab (requirement #7): power VMs/domains on and
off, check connectivity, trigger recovery.

Thin wrapper over isp-ddos-ryu/deploy/vm-lab/vmlab_common (govc_ops,
ssh_ops, inventory) and the already-validated per-domain Ansible reconnect
playbooks. This module intentionally does not reimplement VMware power
control, SSH orchestration or recovery logic: isp-ddos-ryu already has that,
validated against the real 23-VM lab, and duplicating it here would be the
exact kind of unnecessary addition the instrumentation plan is trying to
avoid (see docs/INSTRUMENTATION_PLAN.md §6, decision for Fase 5).
"""
from __future__ import annotations
import subprocess
import sys
from pathlib import Path

ISP_DDOS_RYU = Path('/home/ubuntu/isp-ddos-ryu')
VM_LAB = ISP_DDOS_RYU / 'deploy/vm-lab'
RECONNECT_PLAYBOOKS = {
    'mobile': 'reconnect_mobile_domain.yml',
    'fixed': 'reconnect_fixed_domain.yml',
    'peering': 'reconnect_peering_domain.yml',
}


def _vmlab_common():
    if not VM_LAB.is_dir():
        raise RuntimeError(f'isp-ddos-ryu/deploy/vm-lab not found at {VM_LAB}; '
                            'lab actions require running on a host with that checkout')
    if str(VM_LAB) not in sys.path:
        sys.path.insert(0, str(VM_LAB))
    import vmlab_common.govc_ops as govc_ops
    import vmlab_common.inventory as inventory
    import vmlab_common.ssh_ops as ssh_ops
    return govc_ops, inventory, ssh_ops


def power_states():
    """{vm_name: 'poweredOn'|'poweredOff'|...} for every VM, via govc."""
    govc_ops, _, _ = _vmlab_common()
    return govc_ops.power_states()


def power_domain(domain, on):
    """Power every VM in a domain on/off. Returns {vm_name: ok}."""
    govc_ops, inventory, _ = _vmlab_common()
    nodes = inventory.nodes_by_domain(domain)
    if not nodes:
        raise ValueError(f'Unknown or empty domain: {domain}')
    return {node.name: govc_ops.power(node.name, on) for node in nodes}


def connectivity_check(domain, command='echo ok'):
    """Run a lightweight command on every node of a domain over the
    already-established SSH path. A failing/unreachable node is reported in
    the result, not raised, so it never hides the state of the rest of the
    domain."""
    _, inventory, ssh_ops = _vmlab_common()
    nodes = inventory.nodes_by_domain(domain)
    if not nodes:
        raise ValueError(f'Unknown or empty domain: {domain}')
    results = {}
    for node in nodes:
        try:
            result = ssh_ops.run(node.name, command)
            results[node.name] = dict(ok=getattr(result, 'returncode', 1) == 0,
                                       stdout=getattr(result, 'stdout', None),
                                       stderr=getattr(result, 'stderr', None))
        except Exception as exc:
            results[node.name] = dict(ok=False, error=str(exc))
    return results


def recover_domain(domain, check=False, extra_args=None):
    """Run the already-validated Ansible reconnect playbook for a domain.

    check=True runs ansible-playbook in --check (dry-run) mode. Domains
    without a dedicated reconnect playbook (today: enterprise) raise
    ValueError rather than silently doing nothing.
    """
    playbook = RECONNECT_PLAYBOOKS.get(domain)
    if playbook is None:
        raise ValueError(f'No recovery playbook for domain: {domain} (have: {sorted(RECONNECT_PLAYBOOKS)})')
    path = VM_LAB / 'ansible/playbooks' / playbook
    if not path.is_file():
        raise RuntimeError(f'Reconnect playbook missing on disk: {path}')
    cmd = ['ansible-playbook', str(path)]
    if check:
        cmd.append('--check')
    if extra_args:
        cmd += list(extra_args)
    proc = subprocess.run(cmd, cwd=str(VM_LAB / 'ansible'), capture_output=True, text=True, timeout=900)
    return dict(domain=domain, playbook=playbook, returncode=proc.returncode,
                stdout=proc.stdout[-5000:], stderr=proc.stderr[-5000:])
