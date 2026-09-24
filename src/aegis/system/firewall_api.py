"""Unica leitura/escrita real do firewall no processo (COM HNetCfg.FwPolicy2).

Vivem aqui tanto o provedor de leitura do motor (sem admin) quanto o que o
AegisApply.exe usa no caminho elevado. Nomes/valores dos enums seguem
NET_FW_RULE_DIRECTION / NET_FW_ACTION / NET_FW_IP_PROTOCOL /
NET_FW_PROFILE_TYPE2; a constante EventLog e canais ficam em eventlog.py.
"""
from __future__ import annotations

from typing import Callable, List, Optional

from aegis.firewall import RuleInfo
from aegis.models import RuleSpec

DIRECTION_TO_COM = {"in": 1, "out": 2}
COM_TO_DIRECTION = {1: "in", 2: "out"}
ACTION_TO_COM = {"allow": 1, "block": 0}
COM_TO_ACTION = {0: "block", 1: "allow"}
PROTOCOL_TO_COM = {"tcp": 6, "udp": 17, "any": 256}
COM_TO_PROTOCOL = {6: "tcp", 17: "udp", 256: "any"}
PROFILE_FLAGS = {"domain": 1, "private": 2, "public": 4}


def profiles_from_mask(mask: int):
    return tuple(name for name, flag in PROFILE_FLAGS.items() if mask & flag)


def profiles_to_mask(names) -> int:
    return sum(PROFILE_FLAGS[n] for n in names)


def ruleinfo_from_com(rule) -> RuleInfo:
    name = rule.Name or ""
    return RuleInfo(
        name=name,
        direction=COM_TO_DIRECTION.get(rule.Direction, "?"),
        action=COM_TO_ACTION.get(rule.Action, "?"),
        protocol=COM_TO_PROTOCOL.get(rule.Protocol, str(rule.Protocol)),
        local_ports=rule.LocalPorts or "",
        profiles=profiles_from_mask(int(rule.Profiles or 0)),
        enabled=bool(rule.Enabled),
        program=rule.ApplicationName or "",
        built_in=not name.startswith("Aegis "),
    )


class ComFirewallProvider:
    def __init__(self, policy=None, rule_factory: Optional[Callable] = None):
        if policy is None:
            from comtypes.client import CreateObject  # import tardio: so no runtime Windows
            policy = CreateObject("HNetCfg.FwPolicy2")
            if rule_factory is None:
                rule_factory = lambda: CreateObject("HNetCfg.FwRule")  # noqa: E731
        self._policy = policy
        self._rule = rule_factory or (lambda: None)

    def list_rules(self) -> List[RuleInfo]:
        return [ruleinfo_from_com(r) for r in self._policy.Rules]

    def get_rule(self, name: str) -> Optional[RuleInfo]:
        # Contrato IFirewallProvider: o firewall do Windows nao distingue
        # caixa no nome — a varredura tambem nao.
        wanted = name.lower()
        for r in self.list_rules():
            if r.name.lower() == wanted:
                return r
        return None

    def add_rule(self, spec: RuleSpec) -> None:
        rule = self._rule()
        rule.Name = spec.name
        rule.Description = spec.description or f"Aegis v0 — {spec.name}"
        rule.Direction = DIRECTION_TO_COM[spec.direction]
        rule.Action = ACTION_TO_COM[spec.action]
        rule.Protocol = PROTOCOL_TO_COM[spec.protocol]
        rule.LocalPorts = spec.local_ports or "*"
        rule.RemotePorts = spec.remote_ports or "*"
        rule.Profiles = profiles_to_mask(spec.profiles)
        rule.Enabled = bool(spec.enabled)
        if spec.program:
            rule.ApplicationName = spec.program
        self._policy.Rules.Add(rule)

    def remove_rule(self, name: str) -> None:
        self._policy.Rules.Remove(name)

    def raw_policy(self):
        """Escapamento controlado para o helper: o op set_enabled precisa do
        objeto COM vivo para mutar Enabled; a leitura continua via get_rule.
        Nao usar para nada novo sem revisitar este contrato."""
        return self._policy
