import json
from pathlib import Path

from aegis.models import RuleSpec
from aegis.system.elevate import ElevatedRunner, build_elevation_command
from fakes import FakeFirewallProvider
from aegis.system import elevate
from aegis.system.firewall_api import ruleinfo_from_com
import aegis.apply as apply_mod


def test_comando_e_uac_visivel_e_espera():
    cmd = build_elevation_command(Path("C:\\AegisApply.exe"),
                                  Path("r.json"), Path("s.json"))
    joined = " ".join(cmd)
    assert "powershell" in joined.lower()
    assert "-Verb RunAs" in joined and "-Wait" in joined
    assert "AegisApply.exe" in joined


def test_runner_escreve_le_protocolo_e_cancelo(tmp_path, monkeypatch):
    def fake_runner(request_path, result_path):
        req = json.loads(Path(request_path).read_text(encoding="utf-8"))
        assert req["op"] == "add_rule"
        if req["spec"]["name"] == "negado":
            Path(result_path).write_text(json.dumps(
                {"ok": False, "motivo": "UAC cancelado"}), encoding="utf-8")
    monkeypatch.setattr(elevate, "_spawn", fake_runner)
    run = ElevatedRunner(Path("AegisApply.exe"), tmp_path)
    spec = RuleSpec(name="negado", direction="in", action="allow",
                    protocol="tcp", local_ports="80", program="p")
    assert run({"op": "add_rule", "spec": spec.to_dict()}) == \
        {"ok": False, "motivo": "UAC cancelado"}


def test_result_faltante_e_tratado_como_cancelamento(tmp_path, monkeypatch):
    monkeypatch.setattr(elevate, "_spawn", lambda *a: None)  # nao escreve nada
    run = ElevatedRunner(Path("x.exe"), tmp_path)
    res = run({"op": "noop"})
    assert res["ok"] is False and "cancelado" in res["motivo"]


def test_spawn_quebrado_vira_motivo(tmp_path, monkeypatch):
    # R1: spawn que nao dispara (powershell ausente, timeout) nao pode
    # explodir o ApplyService — vira motivo auditavel.
    def boom(*a):
        raise RuntimeError("sem powershell")
    monkeypatch.setattr(elevate, "_spawn", boom)
    run = ElevatedRunner(Path("x.exe"), tmp_path)
    res = run({"op": "noop"})
    assert res["ok"] is False
    assert "sem powershell" in res["motivo"]


def test_result_podre_vira_motivo(tmp_path, monkeypatch):
    # R2: resultado mei-escrito ou podre vira motivo legivel, nunca crash.
    def write_garbage(request_path, result_path):
        Path(result_path).write_text("}{lixo", encoding="utf-8")
    monkeypatch.setattr(elevate, "_spawn", write_garbage)
    run = ElevatedRunner(Path("x.exe"), tmp_path)
    res = run({"op": "noop"})
    assert res["ok"] is False
    assert "ilegivel" in res["motivo"]


def test_sucesso_do_helper_e_repassado_como_esta(tmp_path, monkeypatch):
    # Passthrough: payload ok do helper volta intacto — nenhuma chave
    # inventada nem motivo colado no sucesso.
    def write_ok(request_path, result_path):
        Path(result_path).write_text(json.dumps({"ok": True}),
                                     encoding="utf-8")
    monkeypatch.setattr(elevate, "_spawn", write_ok)
    run = ElevatedRunner(Path("x.exe"), tmp_path)
    assert run({"op": "noop"}) == {"ok": True}


def test_aspas_simples_no_caminho_sao_escapadas():
    # Apostrofo no caminho (C:\Users\o'brien\...) nao pode quebrar a string
    # cotada do PowerShell: aspas viram duplas e o comando segue RunAs -Wait.
    cmd = build_elevation_command(
        Path("C:\\Users\\o'brien\\.aegis\\AegisApply.exe"),
        Path("C:\\Users\\o'brien\\.aegis\\req-1.json"),
        Path("C:\\Users\\o'brien\\.aegis\\res-1.json"))
    joined = " ".join(cmd)
    assert "o''brien" in joined
    assert "-Verb RunAs" in joined