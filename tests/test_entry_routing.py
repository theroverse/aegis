import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _carregar_entry():
    spec = importlib.util.spec_from_file_location("aegis_entry", ROOT / "aegis.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_roteamento_padrao():
    m = _carregar_entry()
    assert m._route([]) == ("gui", [])
    assert m._route(["gui"]) == ("gui", [])
    assert m._route(["gui", "--offline"]) == ("gui", ["--offline"])
    assert m._route(["status"]) == ("cli", ["status"])
    assert m._route(["--offline", "status"]) == ("cli", ["--offline", "status"])


def test_roteamento_atalho_cli_explicito():
    m = _carregar_entry()
    assert m._route(["--cli", "status"]) == ("cli", ["status"])
    assert m._route(["--cli"]) == ("cli", [])


def test_helper_e_procurado_ao_lado_do_exe_quando_frozen(tmp_path, monkeypatch):
    # Simula o congelado: Aegis.exe + AegisApply.exe irmaos no dist.
    (tmp_path / "AegisApply.exe").write_bytes(b"")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "Aegis.exe"))
    from aegis.cli import _resolver_helper
    h = _resolver_helper(tmp_path / "na_existe" / "aegis.py")
    assert h == tmp_path / "AegisApply.exe"


def test_helper_dev_e_o_script_when_sem_exe(tmp_path, monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=True) if hasattr(sys, "frozen") else None
    from aegis.cli import _resolver_helper
    h = _resolver_helper(ROOT / "aegis.py")
    assert h.name == "aegis_apply.py" and h.parent.name == "scripts"
