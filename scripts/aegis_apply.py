#!/usr/bin/env python3
"""Shim de dev: o nucleo do helper elevado agora mora em aegis.apply_cli.

Mantem `python scripts/aegis_apply.py <req> <res>` funcional para inspecao
manual; o exe elevado de verdade e `Aegis.exe --apply <req> <res>` (exe unico).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis.apply_cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2])))
