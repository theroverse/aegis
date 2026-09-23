"""Provider COM real testado com policy duck-typed (sem comtypes no teste).

Desvio honesto do plano (conflito conhecido): o plano descrevia
FakePolicy.Rules como lista pura, mas ComFirewallProvider fala com a forma
real do COM — FwRuleCollection com Add(rule)/Remove(name) e iteracao. Os
fakes abaixo espelham essa forma; as assercoes dos 4 testes permanecem as
do plano.
"""
from typing import Iterator, List

from aegis.models import RuleSpec
from aegis.system.firewall_api import (ACTION_TO_COM, COM_TO_ACTION,
                                        DIRECTION_TO_COM, PROTOCOL_TO_COM,
                                        ComFirewallProvider)


class FakeComRule:
    def __init__(self, **kw):
        self.Name = kw.get("Name", "")
        self.Description = kw.get("Description", "")
        self.Direction = kw.get("Direction", 1)
        self.Action = kw.get("Action", 1)
        self.Protocol = kw.get("Protocol", 6)
        self.LocalPorts = kw.get("LocalPorts", "*")
        self.RemotePorts = kw.get("RemotePorts", "*")
        self.Profiles = kw.get("Profiles", 2)
        self.Enabled = kw.get("Enabled", True)
        self.ApplicationName = kw.get("ApplicationName", "")


class FakeRulesCollection:
    """Espele INetFwRuleCollection: iteravel, `in`, Add(regra), Remove(nome)."""

    def __init__(self, rules=()):
        self._rules: List[FakeComRule] = list(rules)

    def __iter__(self) -> Iterator[FakeComRule]:
        return iter(self._rules)

    def __contains__(self, rule) -> bool:
        return any(r is rule for r in self._rules)

    def __eq__(self, other) -> bool:
        # Adaptacao minima honesta: o plano compara `pol.Rules == []`;
        # a coleção responde igual a uma lista com o mesmo conteudo.
        if isinstance(other, list):
            return self._rules == other
        return NotImplemented

    def Add(self, rule) -> None:  # noqa: N802 — nome do COM real
        self._rules.append(rule)

    def Remove(self, name) -> None:  # noqa: N802 — o COM real remove por nome
        self._rules = [r for r in self._rules if r.Name != name]


class FakePolicy:
    def __init__(self, rules=()):
        self.Rules = FakeRulesCollection(rules)


def test_mapeamentos_da_casa():
    assert DIRECTION_TO_COM["in"] == 1 and DIRECTION_TO_COM["out"] == 2
    assert ACTION_TO_COM["allow"] == 1 and ACTION_TO_COM["block"] == 0
    assert PROTOCOL_TO_COM["tcp"] == 6 and PROTOCOL_TO_COM["any"] == 256
    assert COM_TO_ACTION[0] == "block"


def test_list_rules_converte_para_ruleinfo():
    r = FakeComRule(Name="x", Direction=2, Action=0, Protocol=17,
                    LocalPorts="53", Profiles=5, ApplicationName="C:\\a.exe")
    p = ComFirewallProvider(policy=FakePolicy([r]))
    infos = p.list_rules()
    assert infos[0].direction == "out" and infos[0].action == "block"
    assert infos[0].protocol == "udp"
    assert set(infos[0].profiles) == {"domain", "public"}
    assert infos[0].program == "C:\\a.exe"


def test_add_rule_escreve_propriedades_certinhas():
    created = []
    pol = FakePolicy()
    p = ComFirewallProvider(policy=pol, rule_factory=lambda: created.append(FakeComRule()) or created[-1])
    spec = RuleSpec(name="Aegis · t", direction="in", action="allow",
                    protocol="tcp", local_ports="6881", remote_ports="",
                    program="C:\\a.exe", profiles=("private", "domain"),
                    description="d")
    p.add_rule(spec)
    w = created[0]
    assert (w.Name, w.Direction, w.Action, w.Protocol) == ("Aegis · t", 1, 1, 6)
    assert w.LocalPorts == "6881" and w.RemotePorts == "*"
    assert w.Profiles == 3 and w.ApplicationName == "C:\\a.exe"
    assert w in pol.Rules


def test_remove_usa_nome():
    pol = FakePolicy([FakeComRule(Name="apagar")])
    ComFirewallProvider(policy=pol).remove_rule("apagar")
    assert pol.Rules == []


def test_get_rule_ignora_caixa():
    # Contrato IFirewallProvider (firewall.py): nome do firewall do Windows
    # nao distingue caixa — varredura com lista de RuleInfo valida.
    pol = FakePolicy([FakeComRule(Name="Aegis · Servico", Profiles=7)])
    p = ComFirewallProvider(policy=pol)
    hit = p.get_rule("aegis · servico")
    assert hit is not None and hit.name == "Aegis · Servico"
    assert p.get_rule("inexistente") is None
