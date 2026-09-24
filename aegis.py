#!/usr/bin/env python3
"""Entry da fonte: python aegis.py (GUI) / python aegis.py status (CLI).

A rota e o despacho moram em aegis.entry (fonte de verdade unica) para que o
exe congelado (aegis_exe.py) use exatamente o mesmo comportamento.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Saquina de maquina = UTF-8 por definicao; console Windows em cp1252
# derrubava print com um unico caractere fora da pagina (licao do Sentinel).
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True, encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

_ENTRY_PATH = Path(__file__).resolve()
_SRC_DIR = _ENTRY_PATH.parent / "src"

if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from aegis.entry import dispatch
from aegis.entry import route as _route  # noqa: F401  (exposto p/ testes)

if __name__ == "__main__":
    sys.exit(dispatch(_ENTRY_PATH, sys.argv[1:]))
