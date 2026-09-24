"""Caminho elevado: motor nunca tem admin, o processo RunAs tem.

Protocolo: motor escreve req-<id>.json -> _spawn dispara o ALVO elevado com
-Verb RunAs -Wait -> o alvo escreve res-<id>.json -> motor le. Cancelar/denegar
o UAC = nenhum result = "UAC cancelado — nada tocou o sistema". Os arquivos
req/res ficam no work_dir como trilha forense (nenhuma limpeza deliberada).

Exe UNICO (decisao do usuario sobre a v0 de dois exes): o alvo elevado nao e
mais um AegisApply.exe irmao — e o proprio Aegis.exe em modo oculto
``--apply <req> <res>`` (rota em aegis.entry, nucleo em aegis.apply_cli).
Um "alvo" e o par (executavel, args-fixos-anteriores-a-req/res).
"""
from __future__ import annotations

import json
import subprocess
import uuid
from pathlib import Path
from typing import Any, Dict, List, Tuple

# (exe, args) — args vem ANTES de req/res na linha de comando do alvo.
ElevationTarget = Tuple[Path, List[str]]


def _q(p: Path) -> str:
    # Escapamento PS de string com aspas simples: ' -> ''.
    # Sem isso, caminho com apostrofo (C:\Users\o'brien\...) quebra o parse
    # do PowerShell, nenhum result e escrito e o motor rotula mal a falha
    # dura como "UAC cancelado". Vale para exe, args e caminhos req/res.
    return str(p).replace("'", "''")


def build_elevation_command(target: ElevationTarget, request_path: Path,
                            result_path: Path) -> List[str]:
    exe, args = target
    arglist = ",".join(f"'{_q(a)}'"
                       for a in [*[str(x) for x in args],
                                 str(request_path), str(result_path)])
    ps = (f"Start-Process -FilePath '{_q(Path(exe))}' "
          f"-ArgumentList {arglist} "
          "-Verb RunAs -Wait")
    return ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps]


def _spawn(target: ElevationTarget, request_path: Path,
           result_path: Path) -> None:
    # exe pai --windowed nao tem console; sem CREATE_NO_WINDOW o powershell
    # filho pisca uma janela preta na tela do usuario (licao da casa).
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    subprocess.run(build_elevation_command(target, request_path, result_path),
                   capture_output=True, text=True, timeout=120,
                   creationflags=flags)


_SPAWN_REAL = _spawn  # referencia fixa para distinguir o seam de teste


class ElevatedRunner:
    def __init__(self, target: ElevationTarget, work_dir: Path):
        exe, args = target
        self.target: ElevationTarget = (Path(exe), [str(a) for a in args])
        self.work = Path(work_dir)
        self.work.mkdir(parents=True, exist_ok=True)

    def _fire(self, req: Path, res: Path) -> None:
        # Contrato do seam (tests/test_elevate.py): fake recebe exatamente
        # (request_path, result_path). No caminho real o alvo da instancia e
        # passado junto; quando _spawn foi substituido, chamamos o fake com o
        # contrato de dois argumentos.
        # Aridades distintas: o _spawn REAL recebe 3 args (target, req, res);
        # o fake substituido recebe 2 args (req, res) pelo contrato do plano.
        # Cuidado: um fake permissivo de 3 args com parametro defaultado
        # (ex.: lambda req, res, target=None) passa nos testes mas seria
        # mal roteado aqui — o fake deve aceitar exatamente (req, res).
        if _spawn is _SPAWN_REAL:
            _spawn(self.target, req, res)
        else:
            _spawn(req, res)

    def __call__(self, request: Dict[str, Any]) -> Dict[str, Any]:
        rid = uuid.uuid4().hex[:8]
        req = self.work / f"req-{rid}.json"
        res = self.work / f"res-{rid}.json"
        with open(req, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(request, fh, ensure_ascii=False)
        if not self.target[0].exists():
            # alvo de elevacao ausente: nao existiu prompt UAC para cancelar
            # — dizer "UAC cancelado" seria culpar o usuario por algo que ele
            # nunca viu. req ja escrito fica como trilha forense.
            return {"ok": False, "motivo": f"alvo de elevacao nao encontrado: "
                    f"{self.target[0]} — sem o exe do Aegis nao ha como "
                    "disparar o UAC"}
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
                # alvo morto no meio da escrita: arquivo mei-escrito nao e
                # cancelamento nem sucesso — diz o que e, sem crash.
                return {"ok": False, "motivo": "result ilegivel"}
            motivo = "" if payload.get("ok") else payload.get("motivo", "falha")
            if payload.get("ok"):
                return payload
        return {"ok": False, "motivo": motivo}
