import json
from pathlib import Path

from aegis.models import RuleSpec
from aegis.system.elevate import ElevatedRunner, build_elevation_command
from fakes import FakeFirewallProvider
from aegis.system import elevate
from aegis.system.firewall_api import ruleinfo_from_com
import aegis.apply as apply_mod


def _target(tmp_path):
    # Desde o check "alvo de elevacao nao encontrado" os testes que exercitam
    # o fluxo pos-spawn precisam de um exe existente (conteudo e irrelevante).
    # Alvo do exe UNICO: o proprio Aegis.exe em modo oculto "--apply".
    exe = tmp_path / "Aegis.exe"
    exe.write_bytes(b"")
    return (exe, ["--apply"])


def test_comando_e_uac_visivel_e_espera():
    cmd = build_elevation_command((Path("C:\\Aegis.exe"), ["--apply"]),
                                  Path("r.json"), Path("s.json"))
    joined = " ".join(cmd)
    assert "powershell" in joined.lower()
    assert "-Verb RunAs" in joined and "-Wait" in joined
    assert "Aegis.exe" in joined
    assert "--apply" in joined


def test_runner_escreve_le_protocolo_e_cancelo(tmp_path, monkeypatch):
    def fake_runner(request_path, result_path):
        req = json.loads(Path(request_path).read_text(encoding="utf-8"))
        assert req["op"] == "add_rule"
        if req["spec"]["name"] == "negado":
            Path(result_path).write_text(json.dumps(
                {"ok": False, "motivo": "UAC cancelado"}), encoding="utf-8")
    monkeypatch.setattr(elevate, "_spawn", fake_runner)
    run = ElevatedRunner(_target(tmp_path), tmp_path)
    spec = RuleSpec(name="negado", direction="in", action="allow",
                    protocol="tcp", local_ports="80", program="p")
    assert run({"op": "add_rule", "spec": spec.to_dict()}) == \
        {"ok": False, "motivo": "UAC cancelado"}


def test_result_faltante_e_tratado_como_cancelamento(tmp_path, monkeypatch):
    monkeypatch.setattr(elevate, "_spawn", lambda *a: None)  # nao escreve nada
    run = ElevatedRunner(_target(tmp_path), tmp_path)
    res = run({"op": "noop"})
    assert res["ok"] is False and "cancelado" in res["motivo"]


def test_spawn_quebrado_vira_motivo(tmp_path, monkeypatch):
    # R1: spawn que nao dispara (powershell ausente, timeout) nao pode
    # explodir o ApplyService — vira motivo auditavel.
    def boom(*a):
        raise RuntimeError("sem powershell")
    monkeypatch.setattr(elevate, "_spawn", boom)
    run = ElevatedRunner(_target(tmp_path), tmp_path)
    res = run({"op": "noop"})
    assert res["ok"] is False
    assert "sem powershell" in res["motivo"]


def test_result_podre_vira_motivo(tmp_path, monkeypatch):
    # R2: resultado mei-escrito ou podre vira motivo legivel, nunca crash.
    def write_garbage(request_path, result_path):
        Path(result_path).write_text("}{lixo", encoding="utf-8")
    monkeypatch.setattr(elevate, "_spawn", write_garbage)
    run = ElevatedRunner(_target(tmp_path), tmp_path)
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
    run = ElevatedRunner(_target(tmp_path), tmp_path)
    assert run({"op": "noop"}) == {"ok": True}


def test_aspas_simples_no_caminho_sao_escapadas():
    # Apostrofo no caminho (C:\Users\o'brien\...) nao pode quebrar a string
    # cotada do PowerShell: aspas viram duplas e o comando segue RunAs -Wait.
    # Vale para o exe ALVO, para os args do alvo e para req/res.
    base = "C:\\Users\\o'brien\\.aegis"
    cmd = build_elevation_command(
        (Path(base + "\\Aegis.exe"), [Path(base + "\\aegis.py"), "--apply"]),
        Path(base + "\\req-1.json"), Path(base + "\\res-1.json"))
    joined = " ".join(cmd)
    assert "o''brien" in joined
    assert joined.count("o''brien") == 4
    assert "-Verb RunAs" in joined


def test_alvo_auscente_nao_culpa_uac_que_nao_existiu(tmp_path, monkeypatch):
    # Maquina com o exe alvo ausente: nunca houve prompt UAC para cancelar —
    # o motivo deve dizer "nao encontrado", nunca "UAC cancelado".
    # O spawn nao pode ser disparado e o req fica como trilha forense.
    def spy(*a):
        raise AssertionError("spawn nao pode disparar sem o alvo")
    monkeypatch.setattr(elevate, "_spawn", spy)
    run = ElevatedRunner((tmp_path / "nao-existe.exe", ["--apply"]), tmp_path)
    res = run({"op": "noop"})
    assert res["ok"] is False
    assert "nao encontrado" in res["motivo"]
    assert list(tmp_path.glob("req-*.json")), "trilha forense do pedido"
