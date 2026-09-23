from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Protocol, Tuple

from aegis.models import RuleSpec


@dataclass
class RuleInfo:
    name: str
    direction: str
    action: str
    protocol: str
    local_ports: str
    profiles: Tuple[str, ...]
    enabled: bool
    program: str = ""
    built_in: bool = False  # regra do SO/terceiros: nunca tocar sem mostrar


class IFirewallProvider(Protocol):
    def list_rules(self) -> List[RuleInfo]: ...

    def get_rule(self, name: str) -> Optional[RuleInfo]: ...

    def add_rule(self, spec: RuleSpec) -> None: ...

    def remove_rule(self, name: str) -> None: ...


def _ranges(ports: str):
    out = []
    for p in (ports or "").split(","):
        p = p.strip()
        if not p or p == "*":
            out.append((0, 65535))
        else:
            lo, _, hi = p.partition("-")
            out.append((int(lo), int(hi or lo)))
    return out


def ports_overlap(a: str, b: str) -> bool:
    for lo1, hi1 in _ranges(a):
        for lo2, hi2 in _ranges(b):
            if lo1 <= hi2 and lo2 <= hi1:
                return True
    return False


def find_conflicts(rules: List[RuleInfo], spec: RuleSpec) -> List[RuleInfo]:
    out: List[RuleInfo] = []
    for r in rules:
        if r.name == spec.name:
            out.append(r)
            continue
        same_app = bool(spec.program) and r.program.lower() == spec.program.lower()
        same_proto = r.protocol == spec.protocol or "any" in (r.protocol, spec.protocol)
        if (same_app and same_proto and r.direction == spec.direction
                and ports_overlap(r.local_ports, spec.local_ports or "*")):
            out.append(r)
    return out
