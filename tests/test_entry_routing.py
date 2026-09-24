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


def test_exe_entry_congelado_usa_o_mesmo_dispatch_da_fonte():
    # Guarda anti-drift: scripts/aegis_exe.py (compilado no Aegis.exe) e uma
    # delegacao pura para aegis.entry.dispatch -- a MESMA fonte de verdade do
    # entry da fonte. Carregamos o corpo do modulo (seguro: tudo util esta fora
    # do bloco __main__) e pinamos a identidade do objeto. Se alguem duplicar /
    # bifurcar a logica de dispatch dentro do script, `is` quebra o teste.
    import aegis.entry
    spec = importlib.util.spec_from_file_location(
        "aegis_exe_entry", ROOT / "scripts" / "aegis_exe.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.dispatch is aegis.entry.dispatch


def test_cli_sem_console_devolve_2_e_nao_chama_main(monkeypatch, tmp_path):
    # Exe windowed no terminal sem pai anexavel: o dispatch NAO pode fingir
    # sucesso -- devolve 2 e nem chega a rodar aegis.cli.main (que imprimiria
    # num fluxo morto). O guard e importado tarde por caminho de modulo,
    # entao patchar o atributo em aegis.system.console funciona.
    import aegis.cli
    import aegis.entry
    import aegis.system.console
    monkeypatch.setattr(aegis.system.console, "ensure_cli_console", lambda: False)
    chamada = []
    monkeypatch.setattr(aegis.cli, "main",
                        lambda entry, argv: chamada.append((entry, argv)) or 0)
    assert aegis.entry.dispatch(tmp_path / "aegis.py", ["status"]) == 2
    assert chamada == []  # main spy NUNCA invocado: sem false-success mudo


def test_cli_com_console_segue_para_o_main(monkeypatch, tmp_path):
    # Caminho feliz da rota CLI: guard True -> dispatch delega a main com o
    # resto dos argumentos (from-import tardio le o atributo do modulo, por
    # isso o monkeypatch em aegis.cli.main e efetivo).
    import aegis.cli
    import aegis.entry
    monkeypatch.delattr(sys, "frozen", raising=False)  # da fonte: guard e True
    recebida = []

    def fake_main(entry, argv):
        recebida.append((entry, argv))
        return 7

    monkeypatch.setattr(aegis.cli, "main", fake_main)
    assert aegis.entry.dispatch(tmp_path / "aegis.py", ["--cli", "status"]) == 7
    assert recebida == [(tmp_path / "aegis.py", ["status"])]
