#!/usr/bin/env python3

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

from aegis.cli import main

if __name__ == "__main__":
    main(_ENTRY_PATH)
