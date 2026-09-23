from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from aegis.aiassist import RuleDraft
from aegis.models import RuleSpec
from aegis.settings import read_json_lenient, write_json_atomic

_TRANSICOES = {
    "pendente": {"aprovado", "rejeitado"},
    "aprovado": {"aplicado", "pendente"},
    "rejeitado": set(),
    "aplicado": set(),
}


class DraftStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        payload = read_json_lenient(self.path, fallback={"counter": 0, "drafts": []})
        self._counter = int(payload.get("counter", 0))
        self._drafts: List[RuleDraft] = [self._from_dict(d) for d in payload.get("drafts", [])]

    @staticmethod
    def _to_dict(d: RuleDraft) -> dict:
        return {"draft_id": d.draft_id, "spec": d.spec.to_dict(),
                "rationale": d.rationale, "confidence": d.confidence,
                "checked": d.checked, "origin": d.origin, "status": d.status}

    @staticmethod
    def _from_dict(d: dict) -> RuleDraft:
        return RuleDraft(spec=RuleSpec.from_dict(d["spec"]),
                         rationale=d["rationale"], confidence=d["confidence"],
                         checked=d.get("checked", ""), origin=d.get("origin", "IA"),
                         status=d.get("status", "pendente"),
                         draft_id=d.get("draft_id", ""))

    def _persist(self) -> None:
        write_json_atomic(self.path, {"counter": self._counter,
                                      "drafts": [self._to_dict(d) for d in self._drafts]})

    def add(self, draft: RuleDraft) -> RuleDraft:
        self._counter += 1
        draft.draft_id = f"d{self._counter:03d}"
        self._drafts.append(draft)
        self._persist()
        return draft

    def all(self, status: Optional[str] = None) -> List[RuleDraft]:
        return [d for d in self._drafts if status is None or d.status == status]

    def get(self, draft_id: str) -> RuleDraft:
        for d in self._drafts:
            if d.draft_id == draft_id:
                return d
        raise KeyError(draft_id)

    def set_status(self, draft_id: str, status: str) -> RuleDraft:
        d = self.get(draft_id)
        if status not in _TRANSICOES.get(d.status, set()):
            raise ValueError(f"transicao ilicita: {d.status} -> {status}")
        d.status = status
        self._persist()
        return d
