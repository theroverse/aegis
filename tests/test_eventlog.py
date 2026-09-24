from aegis.system.eventlog import build_query_xml, parse_wevtutil_xml
from aegis.sources import SourceUnavailable
import os
import pytest
import subprocess

# Licao da casa: o processo GUI e --windowed (sem console). Filho de console
# (wevtutil) sem CREATE_NO_WINDOW pisca janela preta na tela a cada poll.
# Fora do Windows o atributo nao existe -> 0 -> inofensivo.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

FIXTURE = """
<Events>
 <Event><System><EventID>2006</EventID><TimeCreated SystemTime="2026-09-23T18:41:02Z"/></System>
 <EventData>
  <Data Name="Application Path">C:\\q\\qbittorrent.exe</Data>
  <Data Name="Protocol">6</Data>
  <Data Name="Filter Name">Firewall</Data>
  <Data Name="Source Address">203.0.113.9</Data>
  <Data Name="Destination Address">192.168.0.10</Data>
  <Data Name="Destination Port">6881</Data>
 </EventData></Event>
 <Event><System><EventID>4</EventID></System><EventData>
  <Data Name="Name">alguma mudança de regra</Data></EventData></Event>
</Events>
"""


def test_query_xml_usa_canal_e_ids():
    q = build_query_xml(minutes=30, event_ids=(2006,))
    assert "Microsoft-Windows-Windows Firewall With Advanced Security" in q
    assert "EventID" in q and "2006" in q


def test_query_sem_ids_nao_filtra():
    assert "EventID" not in build_query_xml(minutes=5, event_ids=())


def test_parse_extrai_evento_de_bloqueio_e_ignora_outros():
    evs = parse_wevtutil_xml(FIXTURE)
    assert len(evs) == 1
    ev = evs[0]
    assert ev.program == "C:\\q\\qbittorrent.exe"
    assert ev.protocol == "tcp" and ev.port == "6881"
    assert ev.direction == "in" and ev.src == "203.0.113.9"


# Snippet real (redigido) de `wevtutil qe ... /f:xml` nesta maquina Win11:
# <Event> irmaos concatenados SEM raiz <Events>, cada um com xmlns default,
# SystemTime com fracoes de segundo e aspas simples nos atributos. O 1o e um
# 2010 (mudanca de perfil, campo a campo do output real) e deve ser ignorado;
# o 2o e um drop sintetico no formato que a documentacao historica do canal usa.
REAL_SHAPE = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
              "<Provider Name='Microsoft-Windows-Windows Firewall With Advanced Security' "
              "Guid='{d1bc9aff-2abf-4d71-9146-ecb2a986eb85}'/><EventID>2010</EventID>"
              "<TimeCreated SystemTime='2026-09-23T18:49:27.5373893Z'/>"
              "<Channel>Microsoft-Windows-Windows Firewall With Advanced Security/Firewall</Channel>"
              "</System><EventData><Data Name='InterfaceGuid'>{37217669-42da-4657-a55b-0d995d328250}</Data>"
              "<Data Name='InterfaceName'>iftype53_32768</Data>"
              "<Data Name='OldProfile'>4</Data><Data Name='NewProfile'>2</Data></EventData></Event>"
              "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
              "<EventID>2006</EventID><TimeCreated SystemTime='2026-09-23T18:50:01.1234567Z'/>"
              "</System><EventData>"
              "<Data Name='Application Path'>C:\\q\\qbittorrent.exe</Data>"
              "<Data Name='Protocol'>17</Data><Data Name='Filter Name'>Firewall</Data>"
              "<Data Name='Source Address'>203.0.113.9</Data>"
              "<Data Name='Destination Address'>192.168.0.10</Data>"
              "<Data Name='Destination Port'>53</Data></EventData></Event>")


def test_parse_saida_real_wevtutil_sem_raiz_com_xmlns():
    evs = parse_wevtutil_xml(REAL_SHAPE)
    assert len(evs) == 1  # o 2010 de perfil e ignorado
    ev = evs[0]
    assert ev.protocol == "udp" and ev.port == "53"
    assert ev.ts == "2026-09-23 18:50:01"  # fracoes de segundo fora
    assert ev.program == "C:\\q\\qbittorrent.exe"


def test_timeout_vira_source_unavailable():
    from aegis.system.eventlog import EventLogBlockSource

    # mesmo sob timeout o filho precisa nascer sem janela: os kwargs vao junto
    # na chamada que explode, entao o spy registra antes de raises.
    vistos = []

    def boom(*a, **k):
        vistos.append(k)
        raise subprocess.TimeoutExpired(cmd="wevtutil", timeout=20)

    with pytest.raises(SourceUnavailable):
        EventLogBlockSource(run=boom).new_events()
    assert vistos and vistos[0].get("creationflags") == _NO_WINDOW


def _proc(returncode=0, stdout="", stderr=""):
    # fake SimpleNamespace: basta expor returncode/stdout/stderr como wevtutil.
    from types import SimpleNamespace
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def _evt_xml(ts):
    # um <Event> de bloqueio minimo com Application Path (para parse nao descartar)
    return ("<Events><Event><System>"
            f"<EventID>2006</EventID><TimeCreated SystemTime=\"{ts}\"/>"
            "</System><EventData>"
            "<Data Name=\"Application Path\">C:\\x\\a.exe</Data>"
            "<Data Name=\"Protocol\">6</Data>"
            "<Data Name=\"Source Address\">203.0.113.9</Data>"
            "<Data Name=\"Destination Address\">192.168.0.10</Data>"
            "<Data Name=\"Destination Port\">443</Data>"
            "</EventData></Event></Events>")


def test_rc_diferente_dezero_declara_indisponivel():
    from aegis.system.eventlog import EventLogBlockSource
    # rc != 0 (canal ausente/acesso negado) deve declarar, nunca fingir ok vazio.
    vistos = []

    def run(*a, **k):
        vistos.append(k)
        return _proc(returncode=15000, stdout="", stderr="canal invalido")

    src = EventLogBlockSource(run=run)
    with pytest.raises(SourceUnavailable) as ei:
        src.new_events()
    assert "15000" in str(ei.value)
    # o canal cego NAO e motivo para abrir janela: o flag vai no mesmo run.
    assert vistos and vistos[0].get("creationflags") == _NO_WINDOW


def test_last_ts_monotonicos():
    from aegis.system.eventlog import EventLogBlockSource
    # 2a leva com max ts MAIS ANTIGO (relogio em retrocesso): nao pode
    # reemitir historico nem regredir _last_ts.
    batches = [
        _proc(stdout=_evt_xml("2026-01-02T00:00:00")),  # mais novo
        _proc(stdout=_evt_xml("2026-01-01T00:00:00")),  # mais antigo
    ]
    src = EventLogBlockSource(run=lambda *a, **k: batches.pop(0))
    first = src.new_events()
    assert len(first) == 1
    high = src._last_ts
    second = src.new_events()
    assert second == []
    assert src._last_ts == high


def test_wevtutil_filho_nasce_sem_janela_de_console():
    # O poll do Monitor chama new_events() a cada ~5s: sem CREATE_NO_WINDOW cada
    # poll pisca uma janela de console na tela do usuario.
    from aegis.system import eventlog as eventlog_mod

    chamadas = []

    def spy(cmd, **kw):
        chamadas.append((cmd, kw))
        return _proc(stdout=_evt_xml("2026-01-02T00:00:00"))

    evs = eventlog_mod.EventLogBlockSource(run=spy).new_events()
    assert len(evs) == 1
    cmd, kw = chamadas[0]
    assert cmd[0] == "wevtutil"
    assert "creationflags" in kw, "filho de console precisa de creationflags"
    assert kw["creationflags"] == _NO_WINDOW
    # constante do modulo = atributo do subprocess (mesma fonte em apply_cli).
    assert eventlog_mod._NO_WINDOW == _NO_WINDOW


@pytest.mark.skipif(os.name != "nt", reason="CREATE_NO_WINDOW so existe no Windows")
def test_no_windows_o_flag_e_o_valor_da_api():
    assert _NO_WINDOW == 0x08000000

