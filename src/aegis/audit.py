from __future__ import annotations

import time
from pathlib import Path


class AuditLog:
    """Historico local legivel: append-only, sem reescrita nem expurgo."""

    def __init__(self, path: Path):
        self.path = Path(path)

    def record(self, action: str, target: str, result: str) -> str:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        # splitlines()+join: uma quebra (\n, \v, \u2028...) em qualquer campo
        # quebraria a invariante de uma linha por registro no historico.
        clean = lambda s: " / ".join(str(s).splitlines())
        line = f"{ts} | {clean(action)} | {clean(target)} | {clean(result)}"
        # "a" + newline="\n" + encoding explicito: o padrao do Windows (cp1252
        # e CRLF) quebraria o "·" dos alvos e o diff entre maquinas.
        with open(self.path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(line + "\n")
        return line

    def read(self, tail: int = 0) -> list[str]:
        # tail>0 devolve so as ultimas linhas (painel da GUI); 0/negativo = tudo.
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        return lines[-tail:] if tail > 0 else lines

