from __future__ import annotations

from typing import Dict, List, Optional

from aegis.firewall import RuleInfo
from aegis.models import RuleSpec

try:  # sources.py chega no Task 5; fakes e compartilhado
    from aegis.sources import SourceUnavailable
except ModuleNotFoundError:
    class SourceUnavailable(Exception):
        pass


class FakeFirewallProvider:
    """IFirewallProvider em memoria; regra.built_in=False sempre —
    use inject() para simular regras do SO."""

    def __init__(self):
        self.stored: Dict[str, RuleInfo] = {}
        self.removes: List[str] = []

    def inject(self, info: RuleInfo):
        self.stored[info.name] = info

    def list_rules(self) -> List[RuleInfo]:
        return list(self.stored.values())

    def get_rule(self, name: str) -> Optional[RuleInfo]:
        return self.stored.get(name)

    def add_rule(self, spec: RuleSpec) -> None:
        self.stored[spec.name] = RuleInfo(
            name=spec.name, direction=spec.direction, action=spec.action,
            protocol=spec.protocol, local_ports=spec.local_ports,
            profiles=tuple(spec.profiles), enabled=spec.enabled,
            program=spec.program)

    def remove_rule(self, name: str) -> None:
        self.removes.append(name)
        self.stored.pop(name, None)


class FakeClock:
    def __init__(self, now=1000.0):
        self.now = float(now)

    def __call__(self) -> float:
        return self.now

    def advance(self, delta: float) -> None:
        self.now += delta


class FakeConnSource:
    def __init__(self, conns=()):
        self.conns = list(conns)

    def connections(self):
        return list(self.conns)


class FakeBlockSource:
    def __init__(self, batches=(), unavailable=False):
        self._batches = list(batches)
        self.unavailable = unavailable

    def new_events(self):
        if self.unavailable:
            raise SourceUnavailable("log de bloqueios desativado")
        return self._batches.pop(0) if self._batches else []
