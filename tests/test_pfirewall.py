from pathlib import Path

from aegis.sources import SourceUnavailable
from aegis.system.pfirewall import PfirewallSource, parse_block_line

LINE = "2026-09-23  18:41:02  DROP  TCP  203.0.113.9  192.168.0.10  54321  6881  60  -  -  -  -  -  C:\\q\\qbittorrent.exe"


def test_parse_bloco_in_com_path():
    ev = parse_block_line(LINE)
    assert ev.direction == "in" and ev.protocol == "tcp"
    assert ev.port == "6881" and ev.program == "C:\\q\\qbittorrent.exe"
    assert ev.src == "203.0.113.9"


def test_parse_src_privado_e_saida():
    ev = parse_block_line("2026-09-23 10:00:00 BLOCK UDP 192.168.0.5 8.8.8.8 53000 53 42")
    assert ev.direction == "out" and ev.port == "53"


def test_parse_ignora_header_linhas_invalidas_e_icmp():
    assert parse_block_line("#Version: 1.5") is None
    assert parse_block_line("") is None
    assert parse_block_line("2026-09-23 10:00:00 ALLOW TCP 1.1.1.1 2.2.2.2") is None
    ev = parse_block_line("2026-09-23 10:00:00 DROP ICMPV6 fe80::1 192.168::2")
    assert ev is not None and ev.protocol == "icmpv6" and ev.port == ""


def test_source_so_le_acrescimo(tmp_path: Path):
    log = tmp_path / "pfirewall.log"
    log.write_text("#Version: 1.5\n" + LINE + "\n", encoding="utf-8")
    src = PfirewallSource(log)
    assert len(src.new_events()) == 1
    assert src.new_events() == []
    with open(log, "a", encoding="utf-8") as fh:
        fh.write("2026-09-23 10:00:00 DROP UDP 10.0.0.1 8.8.8.8 1 2 3\n")
    assert [e.protocol for e in src.new_events()] == ["udp"]
