import socket
import sys
import types

import pytest


class L:
    def __init__(self, ip, port):
        self.ip, self.port = ip, port


class C:
    def __init__(self, t, st, laddr, raddr=None, pid=None):
        self.type, self.status, self.laddr, self.raddr, self.pid = t, st, laddr, raddr, pid


@pytest.fixture()
def fake_psutil(monkeypatch):
    mod = types.ModuleType("psutil")
    mod.net_connections = lambda kind: [
        C(socket.SOCK_STREAM, "ESTABLISHED", L("192.168.0.5", 51000), L("1.1.1.1", 443), 111),
        C(socket.SOCK_DGRAM, "", L("0.0.0.0", 5353), None, None),
        C(socket.SOCK_STREAM, "TIME_WAIT", L("192.168.0.5", 1), L("2.2.2.2", 80), 222),
    ]
    def proc(pid):
        raise mod.Error()
    mod.Error = Exception
    mod.Process = lambda pid: types.SimpleNamespace(name=lambda: "x.exe")
    monkeypatch.setitem(sys.modules, "psutil", mod)
    return mod


def test_so_vivas_e_escuta(fake_psutil):
    from aegis.system.connections import active_connections
    conns = active_connections(proc_name=lambda p: "chrome.exe")
    assert [c.status for c in conns] == ["ESTABLISHED", "LISTENING"]
    assert conns[0].process == "chrome.exe"
    assert conns[1].protocol == "udp" and conns[1].remote == "-"
    assert conns[1].pid == 0
