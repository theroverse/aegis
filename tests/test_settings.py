import json

from aegis.settings import (DEFAULTS, Settings, read_json_lenient,
                            state_dir, write_json_atomic)


def test_defaults_e_dot_get(tmp_path):
    s = Settings(tmp_path / "config.json")
    assert s.get("monitor.dedupe_janela_s") == 60.0
    assert s.get("monitor.nao_existe", "x") == "x"


def test_save_e_carregamento_roundtrip_com_bom(tmp_path):
    path = tmp_path / "config.json"
    s = Settings(path)
    s.data["monitor"]["dedupe_janela_s"] = 30.0
    s.save()
    # reescreve com BOM artificial (o PowerShell Set-Content faz isso)
    raw = path.read_bytes()
    path.write_bytes(b"\xef\xbb\xbf" + raw)
    again = Settings(path)
    assert again.get("monitor.dedupe_janela_s") == 30.0


def test_corrupto_vira_bak_e_default_volta(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("{isso nao e json", encoding="utf-8")
    s = Settings(path)
    assert s.get("monitor.dedupe_janela_s") == 60.0
    assert path.with_suffix(".json.bak").exists()


def test_write_json_atomic_nao_deixa_tmp(tmp_path):
    target = tmp_path / "x.json"
    write_json_atomic(target, {"a": [1, 2]})
    assert json.loads(target.read_text(encoding="utf-8")) == {"a": [1, 2]}
    assert not (tmp_path / "x.json.tmp").exists()


def test_state_dir_cria_pasta(tmp_path):
    d = state_dir(tmp_path / "qualquer")
    assert d.name == ".aegis" and d.exists()


def test_write_json_atomic_unicode_decode_erro_vira_bak(tmp_path):
    path = tmp_path / "config.json"
    # UTF-16 comeca com BOM \xff\xfe, invalido em UTF-8: cai no fallback
    # via UnicodeDecodeError (subclasse de ValueError) ou via json; ambos
    # devem renomear para .bak.
    path.write_bytes("{}".encode("utf-16"))
    assert read_json_lenient(path, fallback={"d": 1}) == {"d": 1}
    assert not path.exists()
    assert path.with_name("config.json.bak").exists()


def test_read_json_lenient_arquivo_ausente(tmp_path):
    assert read_json_lenient(tmp_path / "nao-existe.json", fallback={"d": 1}) == {"d": 1}


def test_write_json_atomic_unique_tmp_sem_resto(tmp_path):
    target = tmp_path / "y.json"
    write_json_atomic(target, {"v": 1})
    write_json_atomic(target, {"v": 2})
    assert json.loads(target.read_text(encoding="utf-8")) == {"v": 2}
    assert list(tmp_path.glob("*.tmp*")) == []
