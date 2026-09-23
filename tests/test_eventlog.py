from aegis.system.eventlog import build_query_xml, parse_wevtutil_xml

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
