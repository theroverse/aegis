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


def test_ponte_so_expoe_metodos_publicos(api):
    # pywebview recursa em atributos publicos nao-callaveis: um .engine
    # publico entregaria ao JS o Engine inteiro, inclusive escritas que
    # pulam a locka _escrita. Nada publico da ponte pode ser atributo.
    for nome in dir(api):
        if nome.startswith("_"):
            continue
        assert callable(getattr(api, nome)), f"atributo publico nao-metodo: {nome}"


def test_status_devolve_formas_json_seguras(api):
    s = _jsonavel(api.status())
    for chave in ("regras_total", "regras_aegis", "conexoes", "bloqueios",
                  "estado_conexoes", "estado_bloqueios", "revisoes_pendentes"):
        assert chave in s
    assert s["estado_bloqueios"]["estado"] == "ok"
    assert s["sessao"] == "sem admin"


def test_status_declara_saude_real_do_log(api):
    # Contrato da ponte para o banner JS: log_bloqueios e booleano e vem da
    # config real (registro), nao da existencia do pfirewall.log. Sem
    # log_state no motor, o conservador e False — banner fica visivel.
    s = _jsonavel(api.status())
    assert s["log_bloqueios"] is False
    api._engine.log_state = type("L", (), {"enabled": lambda self: True})()
    assert _jsonavel(api.status())["log_bloqueios"] is True


def test_rules_filtra_e_marca_o_que_e_do_aegis(api):
    api._engine.provider.inject(RuleInfo(
        name="Aegis · steam udp", direction="out", action="allow",
        protocol="udp", local_ports="3476", profiles=("private",),
        enabled=True, program="C:\\steam\\steam.exe", built_in=False))
    api._engine.provider.inject(RuleInfo(
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
    assert p.parent == api._state / "prompts"


def test_understand_com_hostile_devolve_motivo_sem_explodir(api):
    # Entrada hostil nao pode estourar excecao crua: a ponte sempre devolve
    # {ok: False, motivo} como os outros metodos.
    for hostil in ("nao eh json", "null", "5", "[1,2]"):
        res = _jsonavel(api.understand(hostil))
        assert res["ok"] is False
        assert res["motivo"]


def test_new_rule_e_ingest_serializam_na_mesma_locka(api, monkeypatch):
    # DraftStore nao e thread-safe: pywebview chama a ponte de worker threads.
    # new_rule e ingest_text precisam escrever a fila sob a mesma self._escrita
    # do approve. Vigiamos drafts.add: duas chamadas simultaneas = corrida.
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor

    origem = api._engine.drafts.add
    dentro = []
    sobreposta = []

    def vigiada(draft):
        dentro.append(threading.current_thread())
        if len(dentro) > 1:
            sobreposta.append(True)
        time.sleep(0.02)  # janela larga o bastante para expor a corrida
        try:
            return origem(draft)
        finally:
            dentro.pop()

    monkeypatch.setattr(api._engine.drafts, "add", vigiada)
    specs = [json.dumps(dict(GOOD_SPEC, name=f"Aegis · lote {i}",
                             local_ports=str(9000 + i))) for i in range(6)]
    respostas = [json.dumps([{"rule": dict(GOOD_SPEC, name=f"Aegis · ia {i}",
                                            protocol="tcp",
                                            local_ports=str(8000 + i)),
                              "rationale": "x", "confidence": "media"}])
                 for i in range(6)]
    with ThreadPoolExecutor(max_workers=12) as ex:
        futs = ([ex.submit(api.new_rule, s) for s in specs]
                + [ex.submit(api.ingest_text, r) for r in respostas])
        resultados = [_jsonavel(f.result()) for f in futs]
    assert not sobreposta, "drafts.add chamado por duas threads sem a locka"
    assert all(r["ok"] is True for r in resultados)
    fila = _jsonavel(api.drafts())
    assert len(fila) == 12  # nenhum rascunho perdido
    ids = [d["draft_id"] for d in fila]
    assert len(set(ids)) == 12  # nenhum draft_id duplicado


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
    api._engine.provider.inject(RuleInfo(
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
        chamado["kw"] = kw
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
    # O pywebview 6 so publica metodos sob window.pywebview.api: o js_api
    # precisa de um atributo publico 'aegis_api' para o JS resolver a ponte.
    js_api = chamado["kw"]["js_api"]
    assert isinstance(getattr(js_api, "aegis_api", None), AegisApi)
    eng.stop()


def test_app_js_resolve_ponte_onde_pywebview_publica():
    js = (Path(__file__).resolve().parents[1] / "gui" / "web" / "app.js").read_text(encoding="utf-8")
    assert "window.pywebview.api.aegis_api" in js


def test_ponte_tem_controles_de_janela_e_sao_seguros_sem_janela(api):
    # A titlebar customizada (casca da suite: Sentinel/Vector/Genesis) precisa
    # de min/close/drag do lado Python. Sem janela atribuida (preview no
    # navegador), chamar cada um tem de ser no-op silencioso, nunca excecao.
    for nome in ("win_minimize", "win_close", "win_drag"):
        assert callable(getattr(api, nome)), f"ponte sem {nome}"
        getattr(api, nome)()  # nao pode lancar


def test_win_close_esconde_para_bandeja_pronta_e_destroi_sem_ela(api):
    # Convencao da suite (SentinelHost.ps1): o x da titlebar customizada nao
    # mata o vigia — esconde para a bandeja, e a bandeja e quem manda sair.
    # E o Window do pywebview 6.2.1 NAO tem close(): chamar .close() era o
    # bug do "clico no x e nada acontece". A saida real e destroy().
    class _J:
        def __init__(self):
            self.chamadas = []

        def hide(self):
            self.chamadas.append("hide")

        def destroy(self):
            self.chamadas.append("destroy")

    class _B:
        pronto = True

        def __init__(self):
            self.avisos = 0

        def avisar(self):
            self.avisos += 1

    api._janela = _J()
    bandeja = _B()
    api._bandeja = bandeja
    api.win_close()
    assert api._janela.chamadas == ["hide"] and bandeja.avisos == 1

    api._janela = _J()
    api._bandeja = None  # sem bandeja (preview/headless): x fecha de verdade
    api.win_close()
    assert api._janela.chamadas == ["destroy"]

    class _Bruka:
        pronto = False  # NotifyIcon nao apareceu: esconder sem bandeja = suma

        def avisar(self):
            raise AssertionError("nao deve avisar com bandeja nao-pronta")

    api._janela = _J()
    api._bandeja = _Bruka()
    api.win_close()
    assert api._janela.chamadas == ["destroy"]


def test_run_monta_bandeja_ao_mostrar_a_janela(tmp_path, monkeypatch):
    # NotifyIcon so recebe cliques na thread que bomba mensagens (o app.Run
    # do backend winforms): run() precisa amarrar _montar_bandeja ao evento
    # 'shown' da janela, nunca criar a bandeja na thread principal.
    montada = []
    monkeypatch.setattr("aegis_app._montar_bandeja",
                        lambda janela: montada.append(janela) or object())

    class _Fila:
        def __init__(self):
            self.itens = []

        def __iadd__(self, h):
            self.itens.append(h)
            return self

    class _Eventos:
        def __init__(self):
            self.shown = _Fila()
            self.closed = _Fila()

    class _Janela:
        def __init__(self):
            self.events = _Eventos()

    criado = {}

    def create_window(title, **kw):
        criado["kw"] = kw
        return _Janela()

    stub = types.ModuleType("webview")
    stub.create_window = create_window
    stub.start = lambda **kw: None
    monkeypatch.setitem(sys.modules, "webview", stub)
    prov = FakeFirewallProvider()
    eng = Engine(provider=prov, conn_source=FakeConnSource(),
                 block_source=FakeBlockSource(batches=[]),
                 runner=lambda req: {"ok": False, "motivo": "offline"},
                 anchor=tmp_path / "aegis.py")
    monkeypatch.setattr("aegis_app.make_engine", lambda entry, offline: eng)
    from aegis_app import run
    assert run(tmp_path / "aegis.py", offline=True) == 0
    janela = criado["kw"]["js_api"].aegis_api._janela
    assert janela.events.shown.itens, "run() nao amarrou nada ao events.shown"
    assert not montada, "bandeja criada antes da janela aparecer"
    for h in janela.events.shown.itens:
        h()
    assert montada == [janela]
    assert janela.events.closed.itens, "run() nao amarrou events.closed"
    for h in janela.events.closed.itens:
        h()
    eng.stop()


def test_run_cria_janela_frameless_e_entrega_a_janela_a_ponte(tmp_path, monkeypatch):
    # frameless=True + titlebar propria = janela identica as demais da suite;
    # com moldura nativa o Aegis e o unico app com barra do Windows (e a
    # ponte precisa da janela para min/close/drag).
    criado = {}

    class _Eventos:
        closed = None

        def __iadd__(self, other):
            return self

    class _Janela:
        events = _Eventos()

    def create_window(title, **kw):
        criado["kw"] = kw
        return _Janela()

    stub = types.ModuleType("webview")
    stub.create_window = create_window
    stub.start = lambda **kw: None
    monkeypatch.setitem(sys.modules, "webview", stub)
    prov = FakeFirewallProvider()
    eng = Engine(provider=prov, conn_source=FakeConnSource(),
                 block_source=FakeBlockSource(batches=[]),
                 runner=lambda req: {"ok": False, "motivo": "offline"},
                 anchor=tmp_path / "aegis.py")
    monkeypatch.setattr("aegis_app.make_engine", lambda entry, offline: eng)
    from aegis_app import run
    assert run(tmp_path / "aegis.py", offline=True) == 0
    assert criado["kw"].get("frameless") is True
    assert criado["kw"].get("resizable") is False
    assert isinstance(criado["kw"]["js_api"].aegis_api._janela, _Janela)
    eng.stop()


def test_web_tem_titlebar_arrastavel_e_shell_que_prende_o_menu():
    base = Path(__file__).resolve().parents[1] / "gui" / "web"
    html = (base / "index.html").read_text(encoding="utf-8")
    js = (base / "app.js").read_text(encoding="utf-8")
    css = (base / "app.css").read_text(encoding="utf-8")
    assert 'class="titlebar"' in html
    assert 'id="btnMin"' in html and 'id="btnClose"' in html
    # o x nao fecha o vigia: esconde para a bandeja (convencao da suite)
    assert 'title="Minimizar para a bandeja"' in html
    assert "win_drag" in js and "win_minimize" in js and "win_close" in js
    compacto = "".join(css.split())
    assert ".titlebar{" in compacto
    # o scroll mora no main, nunca no body: senao a sidebar sai de cena
    assert "overflow:hidden" in compacto and "overflow-y:auto" in compacto


def test_css_nao_deixa_overlay_engolir_o_cli():
    # display autoral (flex/block) vence o [hidden] do UA: sem esta regra a
    # overlay ficaria sempre visivel e engoliria todos os cliques da janela.
    css = (Path(__file__).resolve().parents[1] / "gui" / "web" / "app.css").read_text(encoding="utf-8")
    compacto = "".join(css.split())
    assert "[hidden]{display:none!important}" in compacto
    assert "width:100vw" not in compacto  # 100vw + barra vertical = rolamento horizontal fantasma
