"""Nucleo elevado (--apply) com o netsh fingido: contrato de saida + janela.

O netsh so roda aqui, sob UAC, e o teste NUNCA pode executa-lo de verdade (ia
mexer no config do firewall da maquina) — por isso o monkeypatch em
``aegis.apply_cli.subprocess.run`` e obrigatorio, nao conveniencia.
"""
import json
import subprocess
from types import SimpleNamespace

import aegis.apply_cli
from aegis.system import firewall_api

# filho de console de um pai --windowed: sem CREATE_NO_WINDOW pisca janela preta
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _provider_fingido(monkeypatch):
    # main() importa o provedor COM no topo do try (import tardio de proposito):
    # sem fingi-lo o teste tocaria HNetCfg.FwPolicy2 de verdade.
    monkeypatch.setattr(firewall_api, "ComFirewallProvider",
                        lambda *a, **k: SimpleNamespace())


def test_enable_firewall_log_ok_e_netsh_filho_sem_janela(tmp_path, monkeypatch):
    _provider_fingido(monkeypatch)
    chamadas = []

    def fake_run(cmd, **kw):
        chamadas.append((cmd, kw))
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(aegis.apply_cli.subprocess, "run", fake_run)
    req = tmp_path / "req-1.json"
    res = tmp_path / "res-1.json"
    req.write_text(json.dumps({"op": "enable_firewall_log"}), encoding="utf-8")

    assert aegis.apply_cli.main(req, res) == 0
    assert json.loads(res.read_text(encoding="utf-8")) == {"ok": True}

    assert len(chamadas) == 3, "netsh logging: um parametro por chamada"
    for cmd, kw in chamadas:
        assert cmd[0] == "netsh" and "advfirewall" in cmd
        assert "creationflags" in kw, "netsh filho precisa de creationflags"
        assert kw["creationflags"] == _NO_WINDOW
    tails = [cmd[4:] for cmd, _ in chamadas]
    assert tails == [["logging", "allowedconnections", "disable"],
                     ["logging", "droppedconnections", "enable"],
                     ["logging", "filename", tails[2][2]]]
    assert tails[2][2].lower().endswith("pfirewall.log")
    assert aegis.apply_cli._NO_WINDOW == _NO_WINDOW


def test_netsh_falho_devolve_motivo_literal_e_continua_sem_janela(
        tmp_path, monkeypatch):
    _provider_fingido(monkeypatch)
    vistos = []

    def fake_run(cmd, **kw):
        vistos.append((cmd, kw))
        return SimpleNamespace(returncode=1, stdout=b"",
                               stderr="acesso negado".encode("utf-8"))

    monkeypatch.setattr(aegis.apply_cli.subprocess, "run", fake_run)
    req = tmp_path / "req-2.json"
    res = tmp_path / "res-2.json"
    req.write_text(json.dumps({"op": "enable_firewall_log"}), encoding="utf-8")

    assert aegis.apply_cli.main(req, res) == 1
    out = json.loads(res.read_text(encoding="utf-8"))
    assert out["ok"] is False and out["motivo"].startswith("netsh rc=1")
    # falha dura na primeira chamada: parar ali, nao martelar as outras duas
    assert len(vistos) == 1, "netsh falhou no primeiro, nao adianta o resto"
    assert vistos[0][1].get("creationflags") == _NO_WINDOW
