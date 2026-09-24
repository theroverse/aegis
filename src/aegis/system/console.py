"""Guarda de console para o CLI do exe congelado (camada Windows-only).

Por que existe: o Aegis.exe e montado ``--onefile --windowed``, isto e, um
exe de subsistema GUI. Quando o humano roda ``Aegis.exe --cli status`` de um
terminal INTERATIVO, o filho GUI-subsystem nao consegue escrever no console
que herdou: qualquer print() explode com OSError [Errno 22] Invalid argument
e o CLI moraria mudo (ou, pior, fingiria sucesso sem ninguem ver). A saida
honesta e anexar de volta o console do pai (AttachConsole) e reabrir os
fluxos em CONOUT$/CONIN$ antes de imprimir. Com saida redirecionada para
arquivo/pipe (o caso do smoke do build.ps1) os fluxos ja sao validos e o
guarda e um no-op.
"""
from __future__ import annotations

import sys

# wincon.h: ATTACH_PARENT_PROCESS == (DWORD)-1 == 0xFFFFFFFF (conferido na
# documentacao do AttachConsole; 0 seria o PID do processo 0, nao o pai).
_ATTACH_PARENT_PROCESS = 0xFFFFFFFF


def stream_invalid(stream) -> bool:
    """True se o fluxo e None ou nao aceita nem uma escrita vazia + flush.

    Em stream vivo a sonda e inocua (no-op); no stream morto de um exe
    windowed o write("") levanta OSError EINVAL -- exatamente a falha do
    bug que este modulo corrige."""
    if stream is None:
        return True
    try:
        stream.write("")
        stream.flush()
    except OSError:
        return True
    return False


def ensure_cli_console(kernel32=None, opener=None) -> bool:
    """Garante stdout/stderr escreviveis para o CLI congelado.

    Devolve True quando ha console utilizavel (ou nao era preciso mexer);
    False quando nao foi possivel -- nesse caso NAO toca em sys.*, deixando
    o chamador decidir o fallback honesto. Os parametros sao injetaveis por
    teste (offline, sem ctypes real); os padroes tardios (``ctypes.windll``
    e o ``open`` nativo) so rodam no caminho congelado de verdade.
    """
    if not getattr(sys, "frozen", False):
        return True  # da fonte: stdio de verdade sempre existe
    if not stream_invalid(sys.stdout) and not stream_invalid(sys.stderr):
        return True  # console real ou redirecionado: no-op deliberado
    if kernel32 is None:
        import ctypes  # tardio e com motivo: esta camada e a unica Windows-only
        kernel32 = ctypes.windll.kernel32
    if opener is None:
        opener = open
    if not kernel32.AttachConsole(_ATTACH_PARENT_PROCESS):
        return False  # sem console do pai para anexar: falha declarada
    try:
        # Abre os tres ANTES de atribuir: se CONOUT$ falhar no meio,
        # sys.* fica inteiro como estava (nada de fluxo meio-reaberto).
        out = opener("CONOUT$", "w", encoding="utf-8", errors="replace")
        err = opener("CONOUT$", "w", encoding="utf-8", errors="replace")
        fim = opener("CONIN$", "r")
    except Exception:
        return False
    sys.stdout, sys.stderr, sys.stdin = out, err, fim
    return True
