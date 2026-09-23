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


# Cobre os caminhos de name_for que a fixture do plano deixou sem pin:
# psutil.Process lancando psutil.Error no meio do poll -> fallback "?".
def test_process_desaparecido_meio_a_poll_vira_interrogacao(monkeypatch):
    class ErroSumiu(Exception):
        pass

    mod = types.ModuleType("psutil")
    mod.net_connections = lambda kind: [
        C(socket.SOCK_STREAM, "ESTABLISHED", L("10.20.30.40", 44444), L("8.8.8.8", 443), 111),
    ]
    mod.Error = ErroSumiu
    def proc(pid):
        raise ErroSumiu("processo sumiu entre o scan e o nome")
    mod.Process = proc
    monkeypatch.setitem(sys.modules, "psutil", mod)

    from aegis.system.connections import active_connections
    conns = active_connections()
    assert len(conns) == 1
    assert conns[0].process == "?"
    assert conns[0].status == "ESTABLISHED"


# Cobre o caminho padrao de name_for sem callback (psutil.Process(pid).name())
# e o "?" do UDP sem pid, o golden path usado pela GUI/monitor que o fixture
# do plano nao pinna.
def test_nome_padrao_psutil_e_udp_sem_pid(monkeypatch):
    mod = types.ModuleType("psutil")
    mod.net_connections = lambda kind: [
        C(socket.SOCK_STREAM, "ESTABLISHED", L("10.0.0.1", 9), L("93.184.216.34", 443), 111),
        C(socket.SOCK_DGRAM, "", L("0.0.0.0", 5353), None, None),
    ]
    mod.Error = Exception
    mod.Process = lambda pid: types.SimpleNamespace(name=lambda: "srv.exe")
    monkeypatch.setitem(sys.modules, "psutil", mod)

    from aegis.system.connections import active_connections
    conns = active_connections()
    assert [c.process for c in conns] == ["srv.exe", "?"]
    assert conns[0].local == "10.0.0.1:9"
    assert conns[1].status == "LISTENING"
