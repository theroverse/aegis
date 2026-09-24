"""Nucleo elevado do Aegis: o modo oculto ``--apply`` do Aegis.exe unico.

Movido byte-a-byte de scripts/aegis_apply.py quando a distribuicao passou de
dois exes (Aegis.exe + AegisApply.exe) para um so: o processo elevado e o
PROPRIO Aegis.exe invoked como ``Aegis.exe --apply <req> <res>`` (rota em
aegis.entry.dispatch; alvo montado em aegis.cli._resolver_target).

Entrada: req_path = request JSON, result_path = onde escrever o resultado.
Aplica a operacao via MESMO ComFirewallProvider do processo leitor e escreve
o resultado. Qualquer falha vira motivo literal no result — nunca silencio.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def main(req_path: Path, result_path: Path) -> int:
    request_path, result_path = Path(req_path), Path(result_path)
    dropped_old = False
    try:
        # Import tardio de proposito: o nucleo so toca o provedor COM quando
        # ha operacao para aplicar (e o modulo importa limpo em qualquer SO).
        from aegis.models import RuleSpec
        from aegis.system.firewall_api import ComFirewallProvider
        req = json.loads(request_path.read_text(encoding="utf-8"))
        provider = ComFirewallProvider()
        if req["op"] == "add_rule":
            spec = RuleSpec.from_dict(req["spec"])
            if req.get("replace"):
                # replace remove a de mesmo nome ANTES de adicionar. Atencao:
                # remove+add NAO e atomico — se o add falhar depois do remove,
                # a regra antiga esta perdida (o motivo abaixo diz isso).
                if provider.get_rule(spec.name) is not None:
                    provider.remove_rule(spec.name)
                    dropped_old = True
            provider.add_rule(spec)
            out = {"ok": True}
        elif req["op"] == "remove_rule":
            provider.remove_rule(req["name"])
            out = {"ok": True}
        elif req["op"] == "set_enabled":
            rule = provider.raw_policy().Rules.Item(req["name"])
            rule.Enabled = bool(req["enabled"])
            out = {"ok": True}
        elif req["op"] == "enable_firewall_log":
            # o log de bloqueios do pfirewall.log vem DESLIGADO no Windows: sem
            # isto o monitor nao ve nada. netsh em vez de COM porque a chave de
            # log so aparece no shell; escreve config de firewall, entao so roda
            # aqui, sob UAC visivel, com o motivo literal de volta ao motor.
            log_path = os.path.expandvars(
                "%windir%\\system32\\LogFiles\\Firewall\\pfirewall.log")
            r = subprocess.run(
                ["netsh", "advfirewall", "set", "allprofiles", "logging",
                 "allowed=disable", "blocked=enable",
                 f"logfilename={log_path}"],
                capture_output=True, timeout=60)
            if r.returncode == 0:
                out = {"ok": True}
            else:
                # sem text=True: o output redirecionado do netsh vem em OEM e
                # decodificar pelo codepage do LOCALE estouraria UnicodeDecodeError
                # DEPOIS de um rc=0 — mutacao real marcada ok:False. Captura em
                # bytes e decode defensivo.
                bruto = (r.stderr or b"") + b" / " + (r.stdout or b"")
                saida = " ".join(bruto.decode("utf-8", errors="replace").split())
                out = {"ok": False,
                       "motivo": f"netsh rc={r.returncode}: {saida[:200]}"}
        else:
            out = {"ok": False, "motivo": f"op desconhecido: {req['op']}"}
    except Exception as exc:  # erro literal, nunca silencioso
        motivo = f"{type(exc).__name__}: {exc}"
        if dropped_old:
            motivo += " — regra antiga removida pelo replace e nao recriada"
        out = {"ok": False, "motivo": motivo}
    try:
        with open(result_path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(out, fh, ensure_ascii=False)
    except Exception as exc:  # melhor esforco: nao ha canal de volta ao motor
        # sem result escrito o motor rotula "UAC cancelado" — ecoa no stderr
        # para o log do Start-Process ao menos dizer o que foi.
        print(f"aegis_apply: falha ao escrever result: {type(exc).__name__}: "
              f"{exc}", file=sys.stderr)
    return 0 if out["ok"] else 1
