"""Caminho elevado: motor nunca tem admin, o helper RunAs tem.

Protocolo: motor escreve req-<id>.json -> _spawn dispara o helper elevado
(AegisApply.exe empacotado de scripts/aegis_apply.py) com -Verb RunAs -Wait
-> helper escreve res-<id>.json -> motor le. Cancelar/denegar o UAC = nenhum
result = "UAC cancelado — nada tocou o sistema". Os arquivos req/res ficam no
work_dir como trilha forense (nenhuma limpeza deliberada).
"""
from __future__ import annotations

import json
import subprocess
import uuid
from pathlib import Path
from typing import Any, Dict, List


def _q(p: Path) -> str:
    # Escapamento PS de string com aspas simples: ' -> ''.
    # Sem isso, caminho com apostrofo (C:\Users\o'brien\...) quebra o parse
    # do PowerShell, nenhum result e escrito e o motor rotula mal a falha
    # dura como "UAC cancelado".
    return str(p).replace("'", "''")


def build_elevation_command(helper_exe: Path, request_path: Path,
                            result_path: Path) -> List[str]:
    ps = (f"Start-Process -FilePath '{_q(helper_exe)}' "
          f"-ArgumentList '{_q(request_path)}','{_q(result_path)}' "
          "-Verb RunAs -Wait")
    return ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps]


def _spawn(helper_exe: Path, request_path: Path, result_path: Path) -> None:
    subprocess.run(build_elevation_command(helper_exe, request_path, result_path),
                   capture_output=True, text=True, timeout=120)


_SPAWN_REAL = _spawn  # referencia fixa para distinguir o seam de teste


class ElevatedRunner:
    def __init__(self, helper_exe: Path, work_dir: Path):
        self.helper = Path(helper_exe)
        self.work = Path(work_dir)
        self.work.mkdir(parents=True, exist_ok=True)

    def _fire(self, req: Path, res: Path) -> None:
        # Contrato do seam (tests/test_elevate.py): fake recebe exatamente
        # (request_path, result_path). No caminho real o helper da instancia
        # e passado junto; quando _spawn foi substituido, chamamos o fake com
        # o contrato de dois argumentos.
        # Aridades distintas: o _spawn REAL recebe 3 args (helper, req, res);
        # o fake substituido recebe 2 args (req, res) pelo contrato do plano.
        # Cuidado: um fake permissivo de 3 args com parametro defaultado
        # (ex.: lambda req, res, helper=None) passa nos testes mas seria
        # mal roteado aqui — o fake deve aceitar exatamente (req, res).
        if _spawn is _SPAWN_REAL:
            _spawn(self.helper, req, res)
        else:
            _spawn(req, res)

    def __call__(self, request: Dict[str, Any]) -> Dict[str, Any]:
        rid = uuid.uuid4().hex[:8]
        req = self.work / f"req-{rid}.json"
        res = self.work / f"res-{rid}.json"
        with open(req, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(request, fh, ensure_ascii=False)
        if not self.helper.exists():
            # checkout de dev sem o helper empacotado: nao existiu prompt UAC
            # para cancelar — dizer "UAC cancelado" seria culpar o usuario por
            # algo que ele nunca viu. req ja escrito fica como trilha forense.
            return {"ok": False, "motivo": f"helper nao encontrado: {self.helper} — "
                    "o empacotamento do AegisApply chega na proxima fase"}
        try:
            self._fire(req, res)
        except Exception as exc:
            # spawn furado (powershell ausente, timeout, OSError) nao pode
            # explodir o ApplyService: todo desfecho volta como motivo.
            return {"ok": False, "motivo": f"falha ao disparar elevacao: {exc}"}
        if not res.exists():
            motivo = "UAC cancelado — nada tocou o sistema"
        else:
            try:
                payload = json.loads(res.read_text(encoding="utf-8"))
            except ValueError:
                # helper morto no meio da escrita: arquivo mei-escrito nao e
                # cancelamento nem sucesso — diz o que e, sem crash.
                return {"ok": False, "motivo": "result ilegivel"}
            motivo = "" if payload.get("ok") else payload.get("motivo", "falha")
            if payload.get("ok"):
                return payload
        return {"ok": False, "motivo": motivo}
