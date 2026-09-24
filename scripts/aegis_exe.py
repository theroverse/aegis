#!/usr/bin/env python3
"""Entry CONGELADO: o PyInstaller compila este arquivo em Aegis.exe.

Delegacao pura para aegis.entry.dispatch (mesma fonte de verdade do aegis.py
da fonte), entao GUI/CLI/`--cli` comportam-se identico ao `python aegis.py`.

Mora em scripts/ (nao na raiz) de proposito: o PyInstaller adiciona ao
caminho de busca o DIRETORIO do script de entrada. Se este arquivo ficasse na
raiz, o aegis.py da raiz seria achado como modulo "aegis" e SOMBREARIA o
pacote src/aegis — o import congelado quebraria. Em scripts/ nao ha nenhum
aegis.py, logo "aegis" resolve para o pacote de verdade.

Roda direto daqui tambem: python scripts/aegis_exe.py (GUI) / status (CLI).
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

# ancora = raiz do projeto (um nivel acima de scripts/), onde moram src/ e gui/
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SRC_DIR = _PROJECT_ROOT / "src"

if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from aegis.entry import dispatch

if __name__ == "__main__":
    # dispatch() espera um caminho de ARQUIVO cuja .parent e a raiz do projeto
    # (mesma convengao do aegis.py da fonte): assim tests/, gui/ e .aegis/ sao
    # resolvidos certo. Congelado, ancora no exe real (dist/), em linha com
    # aegis.cli._resolver_helper, que tambem usa sys.executable.
    if getattr(sys, "frozen", False):
        _anchor = Path(sys.executable)
    else:
        _anchor = _PROJECT_ROOT / "aegis.py"
    sys.exit(dispatch(_anchor, sys.argv[1:]))
