from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from aegis.sources import BlockEvent, SourceUnavailable

_BLOCK_ACTIONS = ("DROP", "BLOCK")


def _is_private(ip: str) -> bool:
    return (ip.startswith("192.168.") or ip.startswith("10.")
            or ip.startswith("172.") or ip.startswith("fe80")
            or ip.startswith("127."))


def parse_block_line(line: str) -> Optional[BlockEvent]:
    parts = line.split()
    if len(parts) < 6 or parts[2].upper() not in _BLOCK_ACTIONS:
        return None
    ts = f"{parts[0]} {parts[1]}"
    action, proto, src, dst = parts[2], parts[3].lower(), parts[4], parts[5]
    port = ""
    program = ""
    rest = parts[6:]
    numeric = [t for t in rest[:2] if t.isdigit()]
    if len(numeric) == 2:
        port = numeric[1]  # dst-port: a porta LOCAL do alvo e a que importa p/ regra
    for t in reversed(rest):
        if "\\" in t and t.lower().endswith(".exe"):
            program = t
            break
    if _is_private(src):
        direction = "out"
    elif _is_private(dst):
        direction = "in"
    else:
        direction = ""
    return BlockEvent(ts=ts, direction=direction, protocol=proto, src=src,
                      dst=dst, port=port, program=program)


class PfirewallSource:
    """Le so o acrescimo do log (offset persistido na instancia)."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._offset = 0

    def new_events(self) -> List[BlockEvent]:
        if not self.path.exists():
            raise SourceUnavailable("pfirewall.log nao existe (log desativado)")
        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(self._offset)
            lines = fh.readlines()
            self._offset = fh.tell()
        out = []
        for line in lines:
            ev = parse_block_line(line)
            if ev is not None:
                out.append(ev)
        return out
