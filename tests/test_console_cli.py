"""Guarda de console do CLI congelado (aegis.system.console).

Tudo com fakes injetados: NENhum teste toca ctypes/kernel32 de verdade.
O bug real que estes testes pinam: Aegis.exe (--onefile --windowed) roda
de terminal interativo nao consegue escrever no console herdado -- print()
explode com OSError EINVAL -- e o CLI moraria mudo ou mentiroso.
"""
from __future__ import annotations

import io
import sys
import types

import pytest

from aegis.system import console


class _StreamMorto:
    """Imita o stdout/stderr de um exe windowed no console herdado:
    qualquer escrita levanta OSError [Errno 22] Invalid argument."""

    def __init__(self):
        self.nome = "morto"

    def write(self, s):
        raise OSError(22, "Invalid argument")

    def flush(self):
        raise OSError(22, "Invalid argument")


def _k32(valor, chamadas):
    def attach(pid):
        chamadas.append(pid)
        return valor
    return types.SimpleNamespace(AttachConsole=attach)


def _opener_registra(abertos):
    def opener(name, modo, **kw):
        f = types.SimpleNamespace(nome=name, modo=modo, kw=kw)
        abertos.append(f)
        return f
    return opener


def test_stream_invalid_none_e_write_que_einv():
    # None (caso classico do bootloader windowed) e stream morto contam
    # como invalidos; um stream vivo passa na sonda de no-op.
    assert console.stream_invalid(None) is True
    assert console.stream_invalid(_StreamMorto()) is True
    assert console.stream_invalid(io.StringIO()) is False


def test_ensure_dev_nunca_toca_streams(monkeypatch):
    # Da fonte (nao frozen) o stdio e sempre real: saida True sem abrir
    # nada e sem tocar em sys.*
    monkeypatch.delattr(sys, "frozen", raising=False)
    abertos = []
    chamadas = []
    antes = (sys.stdout, sys.stderr, sys.stdin)
    assert console.ensure_cli_console(
        kernel32=_k32(1, chamadas), opener=_opener_registra(abertos)) is True
    assert (sys.stdout, sys.stderr, sys.stdin) == antes
    assert abertos == [] and chamadas == []


def test_ensure_stdout_valido_e_noop(monkeypatch):
    # Congelado COM saida redirecionada (arquivo/pipe) -- o caso do smoke
    # do build.ps1: fluxo valido -> True sem chamar kernel32 nem opener.
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    ok_out, ok_err = io.StringIO(), io.StringIO()
    monkeypatch.setattr(sys, "stdout", ok_out)
    monkeypatch.setattr(sys, "stderr", ok_err)
    abertos = []
    chamadas = []
    assert console.ensure_cli_console(
        kernel32=_k32(1, chamadas), opener=_opener_registra(abertos)) is True
    assert chamadas == []  # kernel32 fake NAO foi chamado
    assert abertos == []
    assert sys.stdout is ok_out and sys.stderr is ok_err


def test_attach_bem_sucedido_reabre_conout(monkeypatch):
    # Congelado com stdout/stderr mortos no console herdado: anexa o
    # console do pai e reabre os tres fluxos em CONOUT$/CONIN$.
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    out_velho, err_velho = _StreamMorto(), _StreamMorto()
    monkeypatch.setattr(sys, "stdout", out_velho)
    monkeypatch.setattr(sys, "stderr", err_velho)
    abertos = []
    chamadas = []
    # wincon.h: ATTACH_PARENT_PROCESS == (DWORD)-1 == 0xFFFFFFFF (0 e o
    # PID do processo 0, NAO anexa pai nenhum -- conferido na doc).
    assert console._ATTACH_PARENT_PROCESS == 0xFFFFFFFF
    assert console.ensure_cli_console(
        kernel32=_k32(1, chamadas), opener=_opener_registra(abertos)) is True
    assert chamadas == [0xFFFFFFFF]
    assert len(abertos) == 3
    out, err, fim = abertos
    assert out.nome == "CONOUT$" and out.modo == "w"
    assert out.kw == {"encoding": "utf-8", "errors": "replace"}
    assert err.nome == "CONOUT$" and err.modo == "w"
    assert err.kw == {"encoding": "utf-8", "errors": "replace"}
    assert fim.nome == "CONIN$" and fim.modo == "r"
    assert sys.stdout is out and sys.stderr is err and sys.stdin is fim


def test_attach_falhado_devolve_false_sem_mexer(monkeypatch):
    # Sem conseguir anexar console (ex.: sem pai de terminal): False e as
    # streams ficam intactas -- quem chama decide a fallback honesto.
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    out_velho, err_velho = _StreamMorto(), _StreamMorto()
    monkeypatch.setattr(sys, "stdout", out_velho)
    monkeypatch.setattr(sys, "stderr", err_velho)
    antes = (sys.stdout, sys.stderr, sys.stdin)
    abertos = []
    k32 = types.SimpleNamespace(AttachConsole=lambda pid: 0)  # FALSE = falhou
    assert console.ensure_cli_console(
        kernel32=k32, opener=_opener_registra(abertos)) is False
    assert (sys.stdout, sys.stderr, sys.stdin) == antes
    assert abertos == []  # sem attach, nao reabre nada


def test_reabertura_quebrada_devolve_false_sem_mexer(monkeypatch):
    # Attach ok, mas abrir CONOUT$ falha: False e sys.* intocado (nunca
    # deixar metade dos fluxos apontando para lugar novo).
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    out_velho, err_velho = _StreamMorto(), _StreamMorto()
    monkeypatch.setattr(sys, "stdout", out_velho)
    monkeypatch.setattr(sys, "stderr", err_velho)
    antes = (sys.stdout, sys.stderr, sys.stdin)

    def opener_boom(*a, **k):
        raise OSError(22, "no CONOUT for you")

    assert console.ensure_cli_console(
        kernel32=_k32(1, []), opener=opener_boom) is False
    assert (sys.stdout, sys.stderr, sys.stdin) == antes
