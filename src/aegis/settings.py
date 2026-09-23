from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any, Dict

DEFAULTS: Dict[str, Any] = {
    "monitor": {
        "conexoes_intervalo_s": 2.0,
        "bloqueios_intervalo_s": 5.0,
        "dedupe_janela_s": 60.0,
        "anel_tamanho": 500,
    },
    "ia": {"prompt_max_regras": 3},
    "firewall": {"bloqueios_event_ids": []},
}


def write_json_atomic(path: Path, data: Any) -> None:
    path = Path(path)
    # tmp unico por processo: o helper elevado pode escrever no mesmo volume
    # concorrentemente; um nome fixo colidiria entre writers.
    tmp = path.parent / ("%s.tmp.%d" % (path.name, os.getpid()))
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        os.replace(str(tmp), str(path))
    finally:
        # apos os.replace o tmp ja nao existe; isto limpa apenas falhas.
        if tmp.exists():
            tmp.unlink()


def read_json_lenient(path: Path, fallback: Any = None) -> Any:
    path = Path(path)
    try:
        # decode dentro do try: UnicodeDecodeError e subclasse de ValueError,
        # entao arquivos UTF-16/ANSI corrompidos tambien viram .bak.
        raw = path.read_bytes().decode("utf-8-sig")  # BOM-tolerante
        return json.loads(raw)
    except FileNotFoundError:
        return fallback
    except ValueError:
        # .bak sobrescreve o anterior de proposito: v0 nao guarda backups com timestamp.
        path.replace(path.with_name(path.name + ".bak"))
        return fallback


def _merge(base: Dict[str, Any], over: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def state_dir(anchor: Path) -> Path:
    # anchor e o caminho de um arquivo dentro do projeto (ex.: o entry
    # aegis.py); a pasta .aegis/ fica ao lado dele.
    d = Path(anchor).resolve().parent / ".aegis"
    d.mkdir(parents=True, exist_ok=True)
    return d


class Settings:
    def __init__(self, path: Path):
        self.path = Path(path)
        loaded = read_json_lenient(self.path, fallback=None)
        # copia profunda de DEFAULTS como base: sem isso, um config que omite
        # um grupo inteiro faria s.data compartilhar os dicts globais, e
        # mutar s.data corromperia DEFAULTS para todas as instancias.
        self.data = _merge(copy.deepcopy(DEFAULTS), loaded) \
            if isinstance(loaded, dict) else copy.deepcopy(DEFAULTS)

    def get(self, dotted: str, default: Any = None) -> Any:
        cur: Any = self.data
        for part in dotted.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur

    def save(self) -> None:
        write_json_atomic(self.path, self.data)
