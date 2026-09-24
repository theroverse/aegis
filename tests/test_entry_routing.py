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


def test_alvo_elevado_frozen_e_o_exe_unico_com_apply(tmp_path, monkeypatch):
    # Exe UNICO: congelado, o alvo da elevacao e o proprio Aegis.exe em modo
    # oculto --apply -- nao existe mais procura por AegisApply.exe.
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "Aegis.exe"))
    from aegis.cli import _resolver_target
    exe, args = _resolver_target(tmp_path / "na_existe" / "aegis.py")
    assert exe == tmp_path / "Aegis.exe"
    assert args == ["--apply"]


def test_alvo_elevado_dev_e_interpretador_mais_entry(tmp_path, monkeypatch):
    # Da fonte: o alvo elevado e python aegis.py --apply (mesmo dispatch).
    if hasattr(sys, "frozen"):
        monkeypatch.delattr(sys, "frozen", raising=False)
    from aegis.cli import _resolver_target
    exe, args = _resolver_target(ROOT / "aegis.py")
    assert Path(exe) == Path(sys.executable)
    assert args == [str(ROOT / "aegis.py"), "--apply"]


def test_rota_apply_e_oculta_e_rota_para_o_nucleo(tmp_path, monkeypatch):
    import aegis.apply_cli
    import aegis.entry
    req, res = tmp_path / "req.json", tmp_path / "res.json"
    assert aegis.entry.route(["--apply", str(req), str(res)]) == \
        ("apply", [str(req), str(res)])
    recebidos = []
    monkeypatch.setattr(aegis.apply_cli, "main",
                        lambda r, s: recebidos.append((r, s)) or 0)
    rc = aegis.entry.dispatch(tmp_path / "aegis.py",
                              ["--apply", str(req), str(res)])
    assert rc == 0
    assert recebidos == [(req, res)]  # viram Path na rota


def test_rota_apply_sem_args_bastante_falha_honesta_2(tmp_path, monkeypatch):
    import aegis.apply_cli
    import aegis.entry
    chamada = []
    monkeypatch.setattr(aegis.apply_cli, "main",
                        lambda r, s: chamada.append((r, s)) or 0)
    assert aegis.entry.dispatch(tmp_path / "aegis.py", ["--apply"]) == 2
    assert chamada == []  # nucleo nunca invocado sem req+res


def test_rota_apply_nao_toca_a_guarda_de_console(tmp_path, monkeypatch):
    # O helper elevado escreve ARQUIVOS e nunca imprime para console: a guarda
    # do exe windowed (ensure_cli_console) e irrelevante na rota --apply e nao
    # pode ser alcanada (se for, o AssertionError do fake quebra o teste).
    import aegis.apply_cli
    import aegis.entry
    import aegis.system.console

    def veneno():
        raise AssertionError("guarda de console nao vale para --apply")

    monkeypatch.setattr(aegis.system.console, "ensure_cli_console", veneno)
    monkeypatch.setattr(aegis.apply_cli, "main", lambda r, s: 0)
    assert aegis.entry.dispatch(tmp_path / "aegis.py",
                                ["--apply", "r.json", "s.json"]) == 0


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
