import tempfile
from pathlib import Path

from aegis.aiassist import RuleDraft
from aegis.apply import ApplyService
from aegis.audit import AuditLog
from aegis.firewall import RuleInfo
from aegis.models import RuleSpec
from fakes import FakeFirewallProvider

SPEC = RuleSpec(name="Aegis · novo", direction="in", action="allow",
                protocol="tcp", local_ports="8080", program="C:\\a.exe")


def _audit():
    return AuditLog(Path(tempfile.mkdtemp()) / "audit.log")


def draft():
    return RuleDraft(spec=SPEC, rationale="r", confidence="alta")


def test_aplica_verifica_relendo_e_audit():
    provider = FakeFirewallProvider()
    def runner(req):  # protocolo do runner elevado: quem escreve no firewall
        provider.add_rule(RuleSpec.from_dict(req["spec"]))
        return {"ok": True}
    svc = ApplyService(provider, runner, _audit())
    res = svc.apply(draft())
    assert res["ok"] and res["verificada"]
    assert provider.get_rule(SPEC.name) is not None


def test_runner_negado_nao_verifica_e_registra_motivo():
    provider = FakeFirewallProvider()
    svc = ApplyService(provider, lambda req: {"ok": False, "motivo": "UAC cancelado"}, _audit())
    res = svc.apply(draft())
    assert not res["ok"] and res["motivo"] == "UAC cancelado"
    assert provider.get_rule(SPEC.name) is None


def test_conflito_de_porta_para_antes_de_elevar():
    provider = FakeFirewallProvider()
    provider.inject(RuleInfo(name="outra", direction="in", action="allow",
                             protocol="tcp", local_ports="8080",
                             profiles=("private",), enabled=True,
                             program="C:\\a.exe", built_in=False))
    called = []
    svc = ApplyService(provider, lambda req: called.append(req) or {"ok": True}, _audit())
    res = svc.apply(draft())
    assert res["ok"] is False and res["motivo"] == "conflito"
    assert [r["name"] for r in res["conflitos"]] == ["outra"]
    assert called == []  # jamais elevou


def test_conflito_com_nome_igual_pede_substituir_explicitamente():
    provider = FakeFirewallProvider()
    provider.add_rule(SPEC)  # mesma regra ja existe
    svc = ApplyService(provider, lambda req: {"ok": True}, _audit())
    res = svc.apply(draft())
    assert res["motivo"] == "conflito"
    res2 = svc.apply(draft(), replace=True)
    assert res2["ok"] and res2["verificada"]


def test_remover_regra_do_sistema_e_recusada_mostrando():
    provider = FakeFirewallProvider()
    provider.inject(RuleInfo(name="@" "FirewallAPI", direction="in", action="allow",
                             protocol="any", local_ports="*",
                             profiles=("domain",), enabled=True,
                             program="", built_in=True))
    svc = ApplyService(provider, lambda req: {"ok": True}, _audit())
    res = svc.remove("@FirewallAPI")
    assert not res["ok"] and "sistema" in res["motivo"]


def test_remover_regra_aegis_passa_pelo_runner():
    provider = FakeFirewallProvider()
    provider.add_rule(SPEC)
    seen = []
    def runner(req):
        seen.append(req)
        provider.remove_rule(req["name"])
        return {"ok": True}
    svc = ApplyService(provider, runner, _audit())
    res = svc.remove(SPEC.name)
    assert res["ok"] and seen[0]["op"] == "remove_rule"
    assert provider.get_rule(SPEC.name) is None
