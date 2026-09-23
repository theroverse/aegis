from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any, Dict, List

ACTIONS = ("allow", "block")
DIRECTIONS = ("in", "out")
PROTOCOLS = ("tcp", "udp", "any")
PROFILES = ("domain", "private", "public")
CONFIDENCES = ("baixa", "media", "alta")

_PORT_ITEM = re.compile(r"^[0-9]{1,5}(-[0-9]{1,5})?$")


class SpecError(ValueError):
    def __init__(self, errors: List[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def validate_ports(value: str) -> List[str]:
    if not value:
        raise ValueError("porta obrigatoria para tcp/udp")
    parts = [p.strip() for p in value.split(",")]
    if any(p == "*" for p in parts):
        if len(parts) > 1:
            raise ValueError('"*" nao se mistura com portas especificas')
        return ["*"]
    out: List[str] = []
    for p in parts:
        if not p or not _PORT_ITEM.match(p):
            raise ValueError(f"porta invalida: {p!r}")
        lo, _, hi = p.partition("-")
        a, b = int(lo), int(hi) if hi else int(lo)
        if not (0 < a <= 65535 and 0 < b <= 65535) or a > b:
            raise ValueError(f"faixa invalida: {p!r}")
        out.append(p)
    return out


@dataclass
class RuleSpec:
    name: str
    direction: str
    action: str
    protocol: str
    local_ports: str = ""
    remote_ports: str = ""
    program: str = ""
    profiles: tuple = ("private",)
    enabled: bool = True
    description: str = ""

    def __post_init__(self):
        errors: List[str] = []
        if not isinstance(self.name, str) or not self.name.strip():
            errors.append("name: obrigatorio")
        if self.direction not in DIRECTIONS:
            errors.append(f"direction: use {DIRECTIONS}")
        if self.action not in ACTIONS:
            errors.append(f"action: use {ACTIONS}")
        if self.protocol not in PROTOCOLS:
            errors.append(f"protocol: use {PROTOCOLS}")
        if self.protocol != "any" and not (self.local_ports or self.remote_ports):
            errors.append(
                f"local_ports/remote_ports: ao menos uma obrigatoria p/ {self.protocol}"
            )
        for label in ("local_ports", "remote_ports"):
            value = getattr(self, label)
            if value:
                try:
                    canonical = validate_ports(value)
                except ValueError as exc:
                    errors.append(f"{label}: {exc}")
                else:
                    setattr(self, label, ",".join(canonical))
        if isinstance(self.profiles, str) or not self.profiles:
            errors.append("profiles: lista nao-vazia de perfis")
        else:
            self.profiles = tuple(self.profiles)
            bad = [p for p in self.profiles if p not in PROFILES]
            if bad:
                errors.append(f"profiles: invalidos {bad}")
        if (self.action == "allow" and not self.program
                and not (self.local_ports or self.remote_ports)):
            errors.append("program: regra de permitir sem portas exige o executavel")
        if errors:
            raise SpecError(errors)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["profiles"] = list(self.profiles)
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RuleSpec":
        if not isinstance(d, dict):
            raise SpecError([f"esperado objeto JSON, veio {type(d).__name__}"])
        known = set(cls.__dataclass_fields__)
        extra = [f"campo desconhecido: {k}" for k in sorted(set(d) - known)]
        if extra:
            raise SpecError(extra)
        payload = dict(d)
        if isinstance(payload.get("profiles"), list):
            payload["profiles"] = tuple(payload["profiles"])
        try:
            return cls(**payload)
        except TypeError as exc:
            raise SpecError([f"estrutura: {exc}"])
