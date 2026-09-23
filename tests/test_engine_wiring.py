import json
import time

from aegis.cli import main
from aegis.engine import Engine
from aegis.models import RuleSpec
from fakes import FakeBlockSource, FakeConnSource, FakeFirewallProvider

SPEC_JSON = {"name": "Aegis · qbittorrent escuta", "direction": "in",
             "action": "allow", "protocol": "tcp", "local_ports": "6881",
             "remote_ports": "", "program": "C:\\q\\qbittorrent.exe",
             "profiles": ["private"], "enabled": True, "description": ""}


def _apply_req(prov, req):
    """Runner fake: mesmo protocolo do AegisApply sem elevação."""
    if req["op"] == "add_rule":
        prov.add_rule(RuleSpec.from_dict(req["spec"]))
        return {"ok": True}
    if req["op"] == "remove_rule":
        prov.remove_rule(req["name"])
        return {"ok": True}
    return {"ok": False, "motivo": f"op inesperado: {req['op']}"}


def make_engine(tmp_path):
    prov = FakeFirewallProvider()
    return prov, Engine(
        provider=prov, conn_source=FakeConnSource(),
        block_source=FakeBlockSource(batches=[]),
        runner=lambda req: _apply_req(prov, req),
        anchor=tmp_path / "aegis.py")


def test_caminho_completo_bloqueio_a_regra_verificada(tmp_path):
    prov, eng = make_engine(tmp_path)
    eng.start_monitor()
    prompt = eng.ask_ai({"program": r"C:\q\qbittorrent.exe", "direction": "in",
                         "protocol": "tcp", "port": "6881",
                         "origin": "bloqueio observado", "profile": "private",
                         "existing": []})
    assert "6881" in prompt
    assert "qbittorrent.exe" in prompt
    drafts = eng.ingest_ai_response(json.dumps([{
        "rule": SPEC_JSON, "rationale": "porta de escuta", "confidence": "media"}]))
    assert eng.approve_and_apply(drafts[0].draft_id)["verificada"]
    assert prov.get_rule(SPEC_JSON["name"]) is not None
    assert any("regra.aplicada" in line for line in eng.audit.read())
    assert eng.drafts.get(drafts[0].draft_id).status == "aplicado"
    eng.stop()


def test_monitor_roda_em_daemon_e_para_sem_pendurar(tmp_path):
    prov, eng = make_engine(tmp_path)
    eng.start_monitor()
    time.sleep(0.05)
    assert eng._thread.daemon is True
    # thread ainda viva depois do primeiro tick: o loop esta de fato rodando
    # (o intervalo de polling padrao e 2.0s, entao nao damos tempo de
    # popular conexoes aqui; basta provar que nao morreu)
    assert eng._thread.is_alive() is True
    eng.stop()


def test_aprovacao_falhada_pode_ser_retentada_sem_transicao_ilicita(tmp_path):
    prov = FakeFirewallProvider()
    eng = Engine(
        provider=prov, conn_source=FakeConnSource(),
        block_source=FakeBlockSource(batches=[]),
        runner=lambda req: {"ok": False, "motivo": "UAC cancelado"},
        anchor=tmp_path / "aegis.py")
    drafts = eng.ingest_ai_response(json.dumps([{
        "rule": SPEC_JSON, "rationale": "porta de escuta", "confidence": "media"}]))
    draft_id = drafts[0].draft_id
    first = eng.approve_and_apply(draft_id)
    assert not first["verificada"]
    # reaprovacao idempotente: runner falhou e o draft seguiu 'aprovado';
    # reencaminhar nao pode subir ValueError nem perder o motivo
    second = eng.approve_and_apply(draft_id)
    assert second["motivo"] == "UAC cancelado"
    assert not second["verificada"]


def test_monitor_reinicia_apos_parar(tmp_path):
    prov, eng = make_engine(tmp_path)
    eng.start_monitor()
    eng.stop()
    eng.start_monitor()
    time.sleep(0.05)
    assert eng._thread.is_alive() is True
    eng.stop()


def test_cli_offline_status_rules_audit(tmp_path, capsys):
    entry = tmp_path / "aegis.py"
    assert main(entry, ["--offline", "status"]) == 0
    payload = capsys.readouterr().out
    assert '"regras": 1' in payload
    assert main(entry, ["--offline", "rules"]) == 0
    assert "Aegis · exemplo" in capsys.readouterr().out
    assert main(entry, ["--offline", "audit"]) == 0
    capsys.readouterr()
