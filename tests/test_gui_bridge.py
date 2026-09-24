import dataclasses
import json
import sys
import types
from pathlib import Path

import pytest

from aegis.engine import Engine
from aegis.models import RuleSpec
from fakes import FakeBlockSource, FakeConnSource, FakeFirewallProvider
from aegis.firewall import RuleInfo

from aegis_app import AegisApi


GOOD_SPEC = {"name": "Aegis · qbittorrent escuta", "direction": "in",
             "action": "allow", "protocol": "tcp", "local_ports": "6881",
             "remote_ports": "", "program": "C:\\q\\qbittorrent.exe",
             "profiles": ["private"], "enabled": True, "description": ""}


def _apply_req(prov, req):
    """Runner fake: mesmo protocolo do AegisApply, sem elevacao."""
    if req["op"] == "add_rule":
        prov.add_rule(RuleSpec.from_dict(req["spec"]))
        return {"ok": True}
    if req["op"] == "remove_rule":
        prov.remove_rule(req["name"])
        return {"ok": True}
    if req["op"] == "set_enabled":
        for i, r in enumerate(prov.rules):
            if r.name.lower() == req["name"].lower():
                prov.rules[i] = dataclasses.replace(r, enabled=req["enabled"])
                return {"ok": True}
        return {"ok": False, "motivo": "regra nao encontrada"}
    return {"ok": False, "motivo": f"op inesperado: {req['op']}"}


@pytest.fixture()
def api(tmp_path):
    prov = FakeFirewallProvider()
    eng = Engine(provider=prov, conn_source=FakeConnSource(),
                 block_source=FakeBlockSource(batches=[]),
                 runner=lambda req: _apply_req(prov, req),
                 anchor=tmp_path / "aegis.py")
    return AegisApi(eng, tmp_path / "aegis.py")


def _jsonavel(obj):
    # Toda saida da ponte tem de sobreviver a JSON do pywebview.
    return json.loads(json.dumps(obj, ensure_ascii=False, default=str))


def test_status_devolve_formas_json_seguras(api):
    s = _jsonavel(api.status())
    for chave in ("regras_total", "regras_aegis", "conexoes", "bloqueios",
                  "estado_conexoes", "estado_bloqueios", "revisoes_pendentes"):
        assert chave in s
    assert s["estado_bloqueios"]["estado"] == "ok"
    assert s["sessao"] == "sem admin"


def test_rules_filtra_e_marca_o_que_e_do_aegis(api):
    api.engine.provider.inject(RuleInfo(
        name="Aegis · steam udp", direction="out", action="allow",
        protocol="udp", local_ports="3476", profiles=("private",),
        enabled=True, program="C:\\steam\\steam.exe", built_in=False))
    api.engine.provider.inject(RuleInfo(
        name="@FirewallAPI.dll,-23090", direction="in", action="allow",
        protocol="icmpv6", local_ports="*", profiles=("domain",),
        enabled=False, program="", built_in=True))
    tudo = _jsonavel(api.rules("", ""))
    assert len(tudo) == 2
    assert {r["name"]: r["aegis"] for r in tudo} == {
        "Aegis · steam udp": True, "@FirewallAPI.dll,-23090": False}
    so_privado = _jsonavel(api.rules("steam", "private"))
    assert [r["name"] for r in so_privado] == ["Aegis · steam udp"]
    busca = _jsonavel(api.rules("23090", ""))
    assert len(busca) == 1


def test_understand_escreve_prompt_e_devolve_texto(api):
    bloco = json.dumps({"ts": "2026-09-23 18:41:02", "direction": "in",
                        "protocol": "tcp", "src": "-", "dst": "192.168.0.5",
                        "port": "6881",
                        "program": "C:\\q\\qbittorrent.exe", "count": 6})
    res = _jsonavel(api.understand(bloco))
    assert "6881" in res["prompt"]
    assert "qbittorrent" in res["prompt"].lower()
    p = Path(res["path"])
    assert p.exists() and "6881" in p.read_text(encoding="utf-8")
    assert p.parent == api.state / "prompts"


def test_ingest_texto_valido_e_motivo_literal_no_invalido(api):
    resposta = json.dumps([{"rule": GOOD_SPEC, "rationale": "porta de escuta",
                            "confidence": "media"}])
    ok = _jsonavel(api.ingest_text(resposta))
    assert ok["ok"] is True and len(ok["ids"]) == 1
    ruim = _jsonavel(api.ingest_text('{"nao":"eh array"}'))
    assert ruim["ok"] is False and ruim["motivo"]


def test_nova_regra_manual_entra_na_fila_e_spec_ruim_recusa(api):
    criado = _jsonavel(api.new_rule(json.dumps(GOOD_SPEC)))
    assert criado["ok"] is True and criado["draft"]["origin"] == "manual"
    assert criado["draft"]["status"] == "pendente"
    pend = [d for d in _jsonavel(api.drafts()) if d["status"] == "pendente"]
    assert pend and pend[0]["spec"]["name"] == GOOD_SPEC["name"]
    ruim = _jsonavel(api.new_rule(json.dumps(dict(GOOD_SPEC, protocol="sctp"))))
    assert ruim["ok"] is False and "protocol" in ruim["motivo"]


def test_approve_repassa_resultado_e_conflito_vem_serializado(api):
    api.engine.provider.inject(RuleInfo(
        name="outra regra", direction="in", action="allow", protocol="tcp",
        local_ports="6881", profiles=("private",), enabled=True,
        program="C:\\q\\qbittorrent.exe", built_in=True))
    ids = api.ingest_text(json.dumps([{"rule": GOOD_SPEC, "rationale": "x",
                                       "confidence": "media"}]))["ids"]
    r1 = _jsonavel(api.approve(ids[0], False))
    assert r1["ok"] is False and r1["motivo"] == "conflito"
    assert r1["conflitos"][0]["name"] == "outra regra"
    r2 = _jsonavel(api.approve(ids[0], False))  # re-drive nao pode explodir
    assert r2["ok"] is False


def test_reject_terminal_e_motivo_honesto_sem_explodir(api):
    ids = api.ingest_text(json.dumps([{"rule": GOOD_SPEC, "rationale": "x",
                                       "confidence": "baixa"}]))["ids"]
    _jsonavel(api.reject(ids[0]))
    d = next(x for x in _jsonavel(api.drafts()) if x["draft_id"] == ids[0])
    assert d["status"] == "rejeitado"
    assert any("rascunho.rejeitado" in linha for linha in api.audit(50))
    fim = _jsonavel(api.approve(ids[0], False))
    assert fim["ok"] is False and "terminal" in fim["motivo"]


def test_run_usa_webview_stub_sem_janela_real(tmp_path, monkeypatch, capsys):
    chamado = {}

    class _Eventos:
        def __init__(self):
            self.closed = lambda **k: None

        def __iadd__(self, other):
            return self

    class _Janela:
        events = _Eventos()

    def create_window(title, **kw):
        chamado["titulo"] = title
        return _Janela()

    def start(**kw):
        chamado["start"] = True

    stub = types.ModuleType("webview")
    stub.create_window = create_window
    stub.start = start
    monkeypatch.setitem(sys.modules, "webview", stub)
    prov = FakeFirewallProvider()
    eng = Engine(provider=prov, conn_source=FakeConnSource(),
                 block_source=FakeBlockSource(batches=[]),
                 runner=lambda req: {"ok": False, "motivo": "offline"},
                 anchor=tmp_path / "aegis.py")
    monkeypatch.setattr("aegis_app.make_engine",
                        lambda entry, offline: eng)
    rc = AegisApi.__module__  # só garante que o import funcionou
    from aegis_app import run
    rc = run(tmp_path / "aegis.py", offline=True)
    assert rc == 0
    assert chamado.get("start") is True
    assert "Aegis" in chamado["titulo"]
    eng.stop()
