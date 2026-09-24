"""Roteamento e despacho compartilhados do entry do Aegis.

Vive no pacote para ser a UNICA fonte de verdade do comportamento do entry:
a fonte (``python aegis.py``) e o exe congelado (aegis_exe.py -> Aegis.exe)
chamam o MESMO dispatch. Isso evita divergir a rota --cli/gui.

Por que existe um aegis_exe.py separado e nao se congela direto o aegis.py:
o PyInstaller registra o script principal tambem pelo nome do arquivo (stem
"aegis"), o que SOMBRA o pacote "aegis" dentro do importador congelado. Nesse
cenario ``from aegis.cli import main`` re-importa o proprios script (nao um
pacote) e explode com "No module named 'aegis.cli'; 'aegis' is not a package".
Um entry de outro nome (aegis_exe) nao colide e resolve o pacote de verdade.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Sequence, Tuple


def route(argv: Sequence[str]) -> Tuple[str, List[str]]:
    """Sem args ou 'gui' -> janela (com --offline opcional); '--cli' e atalho
    explicito para o CLI; qualquer outra coisa vai para o CLI do Plano A."""
    argv = list(argv)
    if not argv or argv[0] == "gui":
        return ("gui", [a for a in argv[1:] if a == "--offline"])
    if argv[0] == "--cli":
        return ("cli", argv[1:])
    return ("cli", argv)


def dispatch(entry: Path, argv: Sequence[str]) -> int:
    """Abre a janela ou o CLI conforme route(); devolve o exit code.

    Os imports de aegis.cli / aegis_app entram AQUI (tardia) para que a ponte
    GUI so toque webview quando de fato abrir janela, e para que o congelado
    resolva o pacote aegis sem sombra de nome no topo do entry.
    """
    entry = Path(entry)
    modo, resto = route(argv)
    if modo == "gui":
        gui_dir = str(entry.parent / "gui")
        if gui_dir not in sys.path:
            sys.path.insert(0, gui_dir)
        from aegis_app import run
        return run(entry, offline="--offline" in resto)
    from aegis.cli import main
    return main(entry, resto)
