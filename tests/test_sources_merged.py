import pytest

from aegis.sources import BlockEvent, MergedBlockSource, SourceUnavailable


def _ev(port: str) -> BlockEvent:
    return BlockEvent(ts="2026-09-23 10:00:00", direction="in", protocol="tcp",
                      src="203.0.113.9", dst="192.168.0.10", port=port)


class _Fonte:
    """Fonte minima: devolve o lote ou declara-se cega."""

    def __init__(self, eventos=(), erro=None):
        self._eventos = list(eventos)
        self._erro = erro

    def new_events(self):
        if self._erro is not None:
            raise SourceUnavailable(self._erro)
        return list(self._eventos)


def test_fonte_cega_nao_soma_eventos_da_viva():
    # Regression da perda silenciosa: no composite antigo, se o pfirewall.log
    # faltasse a excecao subia DEPOIS de o event log ja ter consumido o lote
    # (o _last_ts interno avancava) e os bloqueios do ciclo desapareciam.
    # Aqui a fonte indisponivel e registrada como cega, mas o que a viva
    # trouxe chega ao monitor.
    merged = MergedBlockSource([_Fonte([_ev("6881")]),
                                _Fonte(erro="pfirewall.log ainda nao existe")])
    eventos = merged.new_events()
    assert [e.port for e in eventos] == ["6881"]


def test_todas_cegas_levanta_com_os_motivos_unidos():
    merged = MergedBlockSource([_Fonte(erro="motivo um"),
                                _Fonte(erro="motivo dois")])
    with pytest.raises(SourceUnavailable) as exc:
        merged.new_events()
    assert str(exc.value) == "motivo um ; motivo dois"


def test_vivas_sem_erro_simplesmente_soma():
    merged = MergedBlockSource([_Fonte([_ev("1")]), _Fonte([_ev("2"), _ev("3")])])
    assert [e.port for e in merged.new_events()] == ["1", "2", "3"]
