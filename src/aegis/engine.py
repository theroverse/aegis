from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Optional

from aegis.aiassist import RuleDraft, build_prompt, parse_drafts
from aegis.apply import ApplyService
from aegis.audit import AuditLog
from aegis.monitor import Monitor
from aegis.review import DraftStore
from aegis.settings import Settings, state_dir


class Engine:
    def __init__(self, provider, conn_source, block_source, runner,
                 anchor: Path, settings: Optional[Settings] = None):
        st = state_dir(anchor)
        self.settings = settings or Settings(st / "config.json")
        self.audit = AuditLog(st / "audit.log")
        self.provider = provider
        self.drafts = DraftStore(st / "drafts.json")
        self.monitor = Monitor(
            conn_source, block_source,
            clock=time.monotonic,
            window=self.settings.get("monitor.dedupe_janela_s"),
            ring_size=self.settings.get("monitor.anel_tamanho"))
        self.apply = ApplyService(provider, runner, self.audit)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start_monitor(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self.monitor.loop,
            args=(self._stop, time.sleep,
                  self.settings.get("monitor.conexoes_intervalo_s"),
                  self.settings.get("monitor.bloqueios_intervalo_s")),
            daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def ask_ai(self, context: dict) -> str:
        """Devolve o prompt ja montado (o motor de IA e do usuario)."""
        return build_prompt(context,
                           max_regras=self.settings.get("ia.prompt_max_regras"))

    def ingest_ai_response(self, text: str):
        added = []
        for draft in parse_drafts(text):
            added.append(self.drafts.add(draft))
        self.audit.record("ia.rascunhos", f"{len(added)}", "na fila de revisao")
        return added

    def approve_and_apply(self, draft_id: str, replace: bool = False):
        draft = self.drafts.get(draft_id)
        if draft.status in ("rejeitado", "aplicado"):
            # estado terminal nao e transicao ilicita a explodir: devolve
            # motivo honesto, sem traceback e sem tocar em nada.
            return {"ok": False,
                    "motivo": f"rascunho em estado terminal '{draft.status}' — nada alterado"}
        if draft.status != "aprovado":
            draft = self.drafts.set_status(draft_id, "aprovado")
        result = self.apply.apply(draft, replace=replace)
        if result.get("verificada"):
            self.drafts.set_status(draft_id, "aplicado")
        elif result.get("motivo") == "conflito":
            self.drafts.set_status(draft_id, "pendente")
        return result
