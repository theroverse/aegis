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
    """'--apply <req> <res>' e o modo OCULTO do helper elevado (exe unico: o
    proprio Aegis.exe se re-invoca com UAC); sem args ou 'gui' -> janela (com
    --offline opcional); '--cli' e atalho explicito para o CLI; qualquer outra
    coisa vai para o CLI do Plano A."""
    argv = list(argv)
    if argv and argv[0] == "--apply":
        return ("apply", argv[1:])
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
    if modo == "apply":
        # Modo oculto do helper (exe unico): o processo elevado e o proprio
        # Aegis.exe, entao a rota --apply precisa de <req> <res>. Sem os dois
        # argumentos nao ha o que aplicar — devolvemos 2 calados: imprimir
        # ajuda aqui seria competir com o console morto do exe windowed, e o
        # alvo so existe chamado pelo ElevateRunner, que sempre passa os dois.
        if len(resto) < 2:
            return 2
        # Import tardio pelo pacote: o nucleo so toca o provedor COM quando de
        # fato ha uma operacao para aplicar (patchavel em teste).
        from aegis.apply_cli import main as helper_main
        return helper_main(Path(resto[0]), Path(resto[1]))
    if modo == "gui":
        gui_dir = str(entry.parent / "gui")
        if gui_dir not in sys.path:
            sys.path.insert(0, gui_dir)
        from aegis_app import run
        return run(entry, offline="--offline" in resto)
    # Guarda de console do exe windowed: Aegis.exe --cli num terminal
    # interativo herda um stdout morto (print explode com OSError EINVAL).
    # Sem anexar o console do pai NAO podemos imprimir nada -- e sair 0
    # calado seria uma mentira. Devolvemos 2 com o aviso possivel.
    # Import tardio pelo pacote: entry nao conhece ctypes, so aegis.system.
    from aegis.system.console import ensure_cli_console
    if not ensure_cli_console():
        aviso = ("aegis: sem console: use um terminal real ou "
                 "-RedirectStandardOutput (exe windowed)")
        try:
            print(aviso, file=sys.stderr)
        except Exception:
            try:
                print(aviso)
            except Exception:
                pass  # ultima tentativa honesta; o exit code 2 e o aviso
        return 2
    from aegis.cli import main
    return main(entry, resto)
