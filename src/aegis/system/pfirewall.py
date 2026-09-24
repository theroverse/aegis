from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from aegis.sources import BlockEvent, SourceUnavailable

_BLOCK_ACTIONS = ("DROP", "BLOCK")


def _is_private(ip: str) -> bool:
    if ip.startswith("172."):
        # 172.16.0.0/12 so: o segundo octeto deve estar em 16..31
        try:
            second = int(ip.split(".")[1])
        except (IndexError, ValueError):
            return False
        return 16 <= second <= 31
    return (ip.startswith("192.168.") or ip.startswith("10.")
            or ip.startswith("fe80") or ip.startswith("127."))


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
    # pfirewall.log NAO cita caminhos: path com espacos divide-se em tokens;
    # o PATH comeca no 1o token com "\" e vai ate o fim (espacos viram 1 espaco so)
    for i, t in enumerate(rest):
        if "\\" in t:
            joined = " ".join(rest[i:])
            if joined.lower().endswith(".exe"):
                program = joined
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
            # ausencia nao prova desativacao: o Windows so cria o arquivo na
            # primeira linha logada — a saude real do log vem do registro.
            raise SourceUnavailable("pfirewall.log ainda nao existe")
        if self._offset > self.path.stat().st_size:
            # log foi limpinado/rotacionado: reler do inicio, nunca ficar cego em silencio
            self._offset = 0
        with open(self.path, "rb") as fh:
            fh.seek(self._offset)
            data = fh.read()
        # leitura binaria: offset exato em bytes, linha parcial so aparece quando estiver completa
        if data.endswith(b"\n"):
            lines = data.split(b"\n")[:-1]
            self._offset += len(data)
        else:
            parts = data.split(b"\n")
            lines = parts[:-1]  # cauda sem "\n" fica para o proximo poll
            self._offset += sum(len(l) + 1 for l in lines)
        out = []
        for raw in lines:
            ev = parse_block_line(raw.decode("utf-8", "replace"))
            if ev is not None:
                out.append(ev)
        return out
