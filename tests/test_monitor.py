import threading
from dataclasses import replace

from aegis.monitor import Monitor
from aegis.sources import BlockEvent, Connection, SourceUnavailable
from fakes import FakeBlockSource, FakeClock, FakeConnSource

EV = BlockEvent(ts="t", direction="in", protocol="tcp", src="", dst="",
                port="6881", program="qbittorrent")


def ev2():
    return replace(EV, port="3476")


def make(**kw):
    clock = FakeClock()
    defaults = dict(conn_source=FakeConnSource(),
                    block_source=FakeBlockSource(batches=[[EV, ev2()]]),
                    clock=clock, window=60.0, ring_size=10)
    defaults.update(kw)
    return Monitor(**defaults)


def test_poll_adiciona_eventos_novos_ao_anel():
    m = make()
    m.poll_blocked()
    assert [e.port for e in m.snapshot()["bloqueios"]] == ["3476", "6881"]


def test_dedupe_na_janela_soma_contador_sem_duplicar_linha():
    src = FakeBlockSource(batches=[[EV], [replace(EV)], [replace(EV)]])
    m = make(block_source=src)
    m.poll_blocked(); m.poll_blocked(); m.poll_blocked()
    feed = m.snapshot()["bloqueios"]
    assert len(feed) == 1 and feed[0].count == 3


def test_fora_da_janela_vira_evento_novo():
    clock = FakeClock()
    src = FakeBlockSource(batches=[[EV], [replace(EV)]])
    m = make(block_source=src, clock=clock)
    m.poll_blocked()
    clock.advance(61.0)
    m.poll_blocked()
    assert len(m.snapshot()["bloqueios"]) == 2


def test_fonte_indisponivel_fica_declurada_nunca_muda():
    m = make(block_source=FakeBlockSource(unavailable=True))
    m.poll_blocked()
    state, motivo = m.snapshot()["estado_bloqueios"]
    assert state == "indisponivel" and "desativado" in motivo


def test_anel_tem_teto():
    batches = [[BlockEvent(ts=f"t{i}", direction="in", protocol="tcp",
               src="", dst="", port=str(1000 + i), program="p")]
               for i in range(12)]
    m = make(block_source=FakeBlockSource(batches=batches), ring_size=5)
    for _ in range(12):
        m.poll_blocked()
    snap = m.snapshot()["bloqueios"]
    # O plano escreve snap[-1] == "1011", mas o feed e mais-novo-primeiro
    # (test_poll_adiciona_eventos_novos_ao_anel fixa ["3476", "6881"]),
    # entao o ultimo = 1011 e a LINHA ZERO; o rabo e o mais antigo, que o
    # teto de 5 conservou. O que o teste quer provar: teto + recentemente
    # vivo, e o que caiu.
    assert len(snap) == 5 and snap[0].port == "1011" and snap[-1].port == "1007"


def test_loop_poliga_conexoes_e_para_no_evento_de_parada():
    stop = threading.Event()
    ticks = []
    conns = [Connection(pid=1, process="x", protocol="tcp",
                        local="127.0.0.1:53", remote="*", status="LISTEN")]
    m = make(conn_source=FakeConnSource(conns=conns))

    def sleep(s):
        ticks.append(s)
        if len(ticks) >= 2:  # dorme 2x e para: o loop termina sozinho
            stop.set()

    m.loop(stop, sleep, conn_s=0.01, block_s=5.0)
    snap = m.snapshot()
    assert snap["conexoes"] == conns  # poll_connections rodou
    # 1a iteracao poliu bloqueios na hora (lote consumido) mesmo com o
    # relogio parado: last comeca em clock()-block_s, nao em 0.0.
    assert [e.port for e in snap["bloqueios"]] == ["3476", "6881"]
    assert len(ticks) == 2


class FonteQuebrada:
    """Nova_events explode uma vez (ex.: ValueError de linha malformada,
    aqui RuntimeError) e depois volta ao normal."""

    def __init__(self):
        self.calls = 0

    def new_events(self):
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("linha de log malformada")
        return []


def test_fonte_quebrada_declara_erro_e_loop_sobrevive():
    stop = threading.Event()
    vistos = []
    m = make(block_source=FonteQuebrada())

    def sleep(s):
        vistos.append(m.blocked_state)  # estado declarado no fim da iteracao
        if len(vistos) >= 2:
            stop.set()

    m.loop(stop, sleep, conn_s=0.01, block_s=5.0)  # nao lancou: thread viva
    # guarda de ultimo recurso: o RuntimeError virou ("erro", motivo) e o
    # loop seguiu; no 2o poll limpo o estado volta a "ok" (nunca fica velho).
    assert vistos[0][0] == "erro" and "malformada" in vistos[0][1]
    assert vistos[1][0] == "ok"
    assert len(vistos) == 2


class FonteConnQuebrada:
    """Fonte de conexoes que so sabe falhar (contrato de sources.py:
    SourceUnavailable/OSError/uma excessao qualquer de implementation)."""

    def __init__(self, exc):
        self._exc = exc

    def connections(self):
        raise self._exc


def test_erro_de_conexoes_nao_contamina_estado_dos_bloqueios():
    # A bug antigo: ValueError no poll_connections caia no try compartilhado
    # e escrevia ("erro", ...) em estado_bloqueios — acusando o inocente.
    m = make(conn_source=FonteConnQuebrada(ValueError("psutil quebrou")))
    m.poll_blocked()
    m.poll_connections()
    snap = m.snapshot()
    assert snap["estado_bloqueios"] == ("ok", "")
    state, motivo = snap["estado_conexoes"]
    assert state == "erro" and "psutil" in motivo


def test_conexoes_indisponiveis_ficam_declaradas_sem_traceback():
    m = make(conn_source=FonteConnQuebrada(SourceUnavailable("psutil ausente")))
    m.poll_connections()
    state, motivo = m.snapshot()["estado_conexoes"]
    assert state == "indisponivel" and "ausente" in motivo
    assert m.snapshot()["estado_bloqueios"] == ("ok", "")
