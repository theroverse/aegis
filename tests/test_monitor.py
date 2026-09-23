from dataclasses import replace

from aegis.monitor import Monitor
from aegis.sources import BlockEvent
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
