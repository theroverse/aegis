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


# --- Task 8 hardening: built_in inegociavel + auditoria imune a falha do runner ---

def test_replace_nao_atropela_regra_builtin():
    provider = FakeFirewallProvider()
    # mesma regra do SO, mesmo nome; replace nao pode remove-la do portao
    provider.inject(RuleInfo(name=SPEC.name, direction="in", action="allow",
                             protocol="tcp", local_ports="8080",
                             profiles=("private",), enabled=True,
                             program="C:\\a.exe", built_in=True))
    called = []
    svc = ApplyService(provider, lambda req: called.append(req) or {"ok": True}, _audit())
    res = svc.apply(draft(), replace=True)
    assert res["ok"] is False and res["motivo"] == "conflito"
    assert called == []  # jamais elevou


def test_replace_true_ainda_bloqueia_conflito_de_porta():
    provider = FakeFirewallProvider()
    provider.inject(RuleInfo(name="outra", direction="in", action="allow",
                             protocol="tcp", local_ports="8080",
                             profiles=("private",), enabled=True,
                             program="C:\\a.exe", built_in=False))
    svc = ApplyService(provider, lambda req: {"ok": True}, _audit())
    res = svc.apply(draft(), replace=True)
    assert res["motivo"] == "conflito"


def test_runner_quebra_vira_audit():
    provider = FakeFirewallProvider()
    def boom(req):  # spawn/JSON pode estourar; mesmo assim tem que deixar rastro
        raise RuntimeError("spawn falhou")
    log = _audit()
    svc = ApplyService(provider, boom, log)
    res = svc.apply(draft())
    assert res["ok"] is False and "spawn falhou" in res["motivo"]
    last = log.read()[-1]
    assert "erro interno" in last and SPEC.name in last


def test_todo_desfecho_deixa_rastro():
    provider = FakeFirewallProvider()
    provider.inject(RuleInfo(name="outra", direction="in", action="allow",
                             protocol="tcp", local_ports="8080",
                             profiles=("private",), enabled=True,
                             program="C:\\a.exe", built_in=False))
    log = _audit()
    svc = ApplyService(provider, lambda req: {"ok": True}, log)
    svc.apply(draft())
    assert log.read()[-1].endswith("nada alterado")


# --- Task 14 (F2): prefixo de propriedade 'Aegis ' exigido no portao ---

def test_nome_sem_prefixo_aegis_e_recusado_antes_de_tocar_o_sistema():
    provider = FakeFirewallProvider()
    called = []
    log = _audit()
    def runner(req):
        called.append(req)
        return {"ok": True}
    svc = ApplyService(provider, runner, log)
    sem_prefixo = RuleDraft(
        spec=RuleSpec(name="qbittorrent escuta", direction="in",
                      action="allow", protocol="tcp", local_ports="6881",
                      program="C:\\q\\qbittorrent.exe"),
        rationale="r", confidence="alta")
    res = svc.apply(sem_prefixo)
    assert res["ok"] is False
    assert res["motivo"].startswith("nome de regra Aegis deve comecar com 'Aegis '")
    assert called == []  # jamais elevou
    assert provider.get_rule(sem_prefixo.spec.name) is None
    assert log.read()[-1].endswith("nada alterado")
