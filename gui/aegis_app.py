"""Casca grafica do Aegis: pywebview + ponte window.aegis_api.

GUI e casca burra: nenhuma decisao mora aqui — so serializacao, filtro e
repasse para o motor (aegis.engine). webview e importado DENTRO de run() para
os testes da ponte rodarem sem janela e sem WebView2 instalado.
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import re
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from aegis.aiassist import AiResponseError, RuleDraft
from aegis.models import RuleSpec, SpecError


def make_engine(entry: Path, offline: bool):
    """Costura testavel: em produção vem de aegis.cli (offline = fakes)."""
    from aegis import cli
    if offline:
        return cli._offline_engine(entry)
    return cli._windows_engine(entry)


class AegisApi:
    """Objeto exposto ao JS como window.aegis_api. Tudo entra/sai JSON-safe."""

    def __init__(self, engine, entry: Path):
        self.engine = engine
        self.entry = Path(entry)
        self.state = engine.audit.path.parent  # .aegis/ ao lado do entry
        self._escrita = threading.Lock()      # nunca dois UACs ao mesmo tempo

    # ---------- leitura ----------
    def status(self) -> Dict[str, Any]:
        snap = self.engine.monitor.snapshot()
        rules = self.engine.provider.list_rules()
        return {
            "regras_total": len(rules),
            "regras_aegis": sum(1 for r in rules if not r.built_in),
            "conexoes": [dataclasses.asdict(c) for c in snap["conexoes"]],
            "bloqueios": [dataclasses.asdict(b) for b in snap["bloqueios"]],
            "estado_conexoes": self._estado(snap["estado_conexoes"]),
            "estado_bloqueios": self._estado(snap["estado_bloqueios"]),
            "revisoes_pendentes": [self._draft(d)
                                   for d in self.engine.drafts.all("pendente")],
            "sessao": "sem admin",
        }

    @staticmethod
    def _estado(t) -> Dict[str, str]:
        return {"estado": t[0], "detalhe": t[1] if len(t) > 1 else ""}

    def rules(self, query: str = "", profile: str = "") -> List[Dict[str, Any]]:
        q = (query or "").lower()
        pf = (profile or "").lower()
        out = []
        for r in self.engine.provider.list_rules():
            if q and q not in r.name.lower() and q not in (r.program or "").lower():
                continue
            if pf and pf not in [p.lower() for p in r.profiles]:
                continue
            d = dataclasses.asdict(r)
            d["aegis"] = not r.built_in
            out.append(d)
        return out

    def drafts(self) -> List[Dict[str, Any]]:
        return [self._draft(d) for d in self.engine.drafts.all()]

    def audit(self, tail: int = 200) -> List[str]:
        return self.engine.audit.read(int(tail) or 200)

    # ---------- IA: prompt em arquivo + ingestao ----------
    def understand(self, block_json: str) -> Dict[str, Any]:
        """Recebe um BlockEvent (JSON.stringify) e devolve o prompt montado,
        gravado em .aegis/prompts/ (padrao Sentinel: o motor de IA e do
        usuario; o arquivo e o ponto de troca)."""
        b = json.loads(block_json)
        program = b.get("program") or "?"
        existentes = [r.name for r in self.engine.provider.list_rules()
                      if program != "?" and (r.program or "").lower() == program.lower()]
        prompt = self.engine.ask_ai({
            "program": program, "direction": b.get("direction", ""),
            "protocol": b.get("protocol", ""), "port": b.get("port", ""),
            "origin": f"bloqueio observado x{b.get('count', 1)} as {b.get('ts', '')}",
            "profile": "private", "existing": existentes or []})
        pasta = self.state / "prompts"
        pasta.mkdir(parents=True, exist_ok=True)
        slug = re.sub(r"[^A-Za-z0-9._-]", "_", Path(program).name or "evento")
        caminho = pasta / f"prompt-{_dt.datetime.now():%Y%m%d-%H%M%S}-{slug}.md"
        com_instrucao = (
            "# Prompt Aegis — responder = APENAS um array JSON de rascunhos, "
            "sem prosa antes ou depois\n\n" + prompt +
            "\n\n---\nCole a resposta da sua IA (Thero/Zeus) na janela do Aegis "
            "ou grave um arquivo <nome>.answer.json ao lado deste.\n")
        caminho.write_text(com_instrucao, encoding="utf-8", newline="\n")
        return {"path": str(caminho), "prompt": prompt}

    def ingest_text(self, text: str) -> Dict[str, Any]:
        try:
            adicionados = self.engine.ingest_ai_response(text)
        except AiResponseError as exc:
            return {"ok": False, "motivo": " ; ".join(exc.errors)}
        except Exception as exc:  # literal, nunca mudo
            return {"ok": False, "motivo": f"{type(exc).__name__}: {exc}"}
        return {"ok": True, "ids": [d.draft_id for d in adicionados]}

    # ---------- fila de revisao ----------
    def approve(self, draft_id: str, replace: bool = False) -> Dict[str, Any]:
        with self._escrita:
            return self.engine.approve_and_apply(str(draft_id),
                                                 replace=bool(replace))

    def reject(self, draft_id: str) -> Dict[str, Any]:
        with self._escrita:
            try:
                d = self.engine.drafts.set_status(str(draft_id), "rejeitado")
            except ValueError as exc:
                return {"ok": False, "motivo": str(exc)}
            nome = d.spec.name if d else str(draft_id)
            self.engine.audit.record("rascunho.rejeitado", nome, "nada alterado")
            return {"ok": True, "status": "rejeitado"}

    def new_rule(self, spec_json: str) -> Dict[str, Any]:
        """Regra manual do humano: vira rascunho 'manual' na fila — continua
        obrigado o clique em Aplicar + UAC. Nada e escrito daqui direto."""
        try:
            spec = RuleSpec.from_dict(json.loads(spec_json))
        except (SpecError, ValueError, TypeError, json.JSONDecodeError) as exc:
            return {"ok": False, "motivo": f"{type(exc).__name__}: {exc}"}
        rascunho = RuleDraft(spec=spec, rationale="criada pelo usuario na aba Regras",
                             confidence="alta", checked="", origin="manual",
                             status="pendente", draft_id="")
        criado = self.engine.drafts.add(rascunho)
        self.engine.audit.record("rascunho.manual", spec.name, "na fila de revisao")
        return {"ok": True, "draft": self._draft(criado)}

    # ---------- escritas elevadas ----------
    def remove_rule(self, name: str) -> Dict[str, Any]:
        with self._escrita:
            return self.engine.apply.remove(str(name))

    def set_enabled(self, name: str, enabled: bool) -> Dict[str, Any]:
        with self._escrita:
            return self.engine.apply.set_enabled(str(name), bool(enabled))

    def enable_firewall_log(self) -> Dict[str, Any]:
        with self._escrita:
            return self.engine.enable_firewall_log()

    @staticmethod
    def _draft(d) -> Dict[str, Any]:
        return {"draft_id": d.draft_id, "status": d.status, "origin": d.origin,
                "rationale": d.rationale, "confidence": d.confidence,
                "checked": d.checked, "spec": d.spec.to_dict()}


def _web_dir() -> Path:
    if getattr(sys, "frozen", False):  # PyInstaller: assets em _MEIPASS
        return Path(getattr(sys, "_MEIPASS")) / "web"
    return Path(__file__).resolve().parent / "web"


def run(entry: Path, offline: bool = False) -> int:
    import webview  # import tardio deliberado: so a janela real precisa dele
    engine = make_engine(Path(entry), offline)
    api = AegisApi(engine, Path(entry))
    engine.start_monitor()
    janela = webview.create_window(
        "Aegis — Escudo de Rede · Theroverse",
        url=str(_web_dir() / "index.html"),
        js_api=api, width=1180, height=760, min_size=(980, 640))

    def _ao_fechar():
        engine.stop()

    try:
        janela.events.closed += _ao_fechar
    except TypeError:  # stubs simples de teste
        pass
    webview.start()
    return 0
