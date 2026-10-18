"""Lab actions (#7): thin wrapper over isp-ddos-ryu/deploy/vm-lab/vmlab_common.

Only the pure-Python error paths are exercised here: this repository can be
deployed without the isp-ddos-ryu checkout present (see README's "Ubicación"
section), and the actual govc/SSH/Ansible calls need the real 23-VM lab.
"""
import pytest
from benign_lab import lab_actions


def test_recover_domain_rejects_a_domain_without_a_reconnect_playbook():
    with pytest.raises(ValueError, match='No recovery playbook'):
        lab_actions.recover_domain('enterprise')


def test_recover_domain_rejects_an_unknown_domain():
    with pytest.raises(ValueError, match='No recovery playbook'):
        lab_actions.recover_domain('satellite')


@pytest.mark.skipif(not lab_actions.VM_LAB.is_dir(), reason='isp-ddos-ryu/deploy/vm-lab not checked out on this host')
def test_power_domain_rejects_an_unknown_or_empty_domain():
    with pytest.raises(ValueError, match='Unknown or empty domain'):
        lab_actions.power_domain('satellite', True)


@pytest.mark.skipif(not lab_actions.VM_LAB.is_dir(), reason='isp-ddos-ryu/deploy/vm-lab not checked out on this host')
def test_vmlab_common_imports_resolve_on_this_host():
    govc_ops, inventory, ssh_ops = lab_actions._vmlab_common()
    assert hasattr(govc_ops, 'power') and hasattr(govc_ops, 'power_states')
    assert hasattr(inventory, 'nodes_by_domain')
    assert hasattr(ssh_ops, 'run')


def test_vmlab_common_raises_clearly_when_the_sibling_checkout_is_missing(monkeypatch):
    monkeypatch.setattr(lab_actions, 'VM_LAB', lab_actions.VM_LAB / 'does-not-exist')
    with pytest.raises(RuntimeError, match='not found'):
        lab_actions._vmlab_common()


class _FakeNode:
    def __init__(self, name):
        self.name = name


class _FakeSshResult:
    """Mirrors vmlab_common.ssh_ops.SshResult's real field name: .rc, not
    .returncode. A live run against the real lab caught this mismatch once;
    this test pins it so it cannot silently come back."""
    def __init__(self, rc, stdout='', stderr=''):
        self.rc, self.stdout, self.stderr = rc, stdout, stderr


def test_connectivity_check_reads_the_real_sshresult_rc_field(monkeypatch):
    fake_inventory = type('M', (), {'nodes_by_domain': staticmethod(lambda d: [_FakeNode('n1'), _FakeNode('n2')])})
    fake_ssh_ops = type('M', (), {'run': staticmethod(lambda name, cmd: _FakeSshResult(0 if name == 'n1' else 1, stdout='ok'))})
    monkeypatch.setattr(lab_actions, '_vmlab_common', lambda: (None, fake_inventory, fake_ssh_ops))
    results = lab_actions.connectivity_check('mobile')
    assert results['n1']['ok'] is True
    assert results['n2']['ok'] is False
