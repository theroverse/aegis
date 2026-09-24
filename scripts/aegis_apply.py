#!/usr/bin/env python3
"""Micro-helper elevado do Aegis v0 (roda como AegisApply.exe, com admin).

Entrada: argv[1] = request path (JSON), argv[2] = result path (JSON).
Aplica a operacao via MESMO ComFirewallProvider do processo leitor e escreve
o resultado. Qualquer falha vira motivo literal no result — nunca silencio.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis.models import RuleSpec  # noqa: E402
from aegis.system.firewall_api import ComFirewallProvider  # noqa: E402


def main(argv):
    request_path, result_path = Path(argv[1]), Path(argv[2])
    dropped_old = False
    try:
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


if __name__ == "__main__":
    sys.exit(main(sys.argv))
