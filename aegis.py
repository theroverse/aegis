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


def _route(argv):
    """Sem args ou 'gui' -> janela (com --offline opcional); qualquer outra
    coisa vai para o CLI do Plano A."""
    if not argv or argv[0] == "gui":
        return ("gui", [a for a in argv[1:] if a == "--offline"])
    return ("cli", argv)


if __name__ == "__main__":
    modo, resto = _route(sys.argv[1:])
    if modo == "gui":
        sys.path.insert(0, str(_ENTRY_PATH.parent / "gui"))
        from aegis_app import run
        sys.exit(run(_ENTRY_PATH, offline="--offline" in resto))
    sys.exit(main(_ENTRY_PATH, resto))
