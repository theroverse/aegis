import dataclasses

from aegis.apply import ApplyService
from aegis.audit import AuditLog
from aegis.firewall import RuleInfo
from fakes import FakeFirewallProvider


def _provider_com_regra_aegis():
    prov = FakeFirewallProvider()
    prov.inject(RuleInfo(name="Aegis · steam udp", direction="out",
                         action="allow", protocol="udp", local_ports="3476",
                         profiles=("private",), enabled=True,
                         program="C:\\steam\\steam.exe", built_in=False))
    prov.inject(RuleInfo(name="regra do SO", direction="in", action="block",
                         protocol="tcp", local_ports="445",
                         profiles=("domain",), enabled=True, program="",
                         built_in=True))
    return prov


def _service(prov, chamadas, resultado=None):
    def runner(req):
        chamadas.append(req)
        if req["op"] == "set_enabled":
            for key, r in list(prov.stored.items()):
                if r.name.lower() == req["name"].lower():
                    prov.stored[key] = dataclasses.replace(
                        r, enabled=req["enabled"])
        return (resultado or {"ok": True})
    return ApplyService(prov, runner, AuditLog(prov._audit_path))


def test_toggle_de_regra_aegis_e_verificado_por_releitura(tmp_path):
    prov = _provider_com_regra_aegis()
    prov._audit_path = tmp_path / "audit.log"
    chamadas = []
    svc = _service(prov, chamadas)
    res = svc.set_enabled("aegis · steam udp", False)   # caixa diferente, de proposito
    assert res["ok"] and res["verificada"] and res["enabled"] is False
    assert chamadas[0] == {"op": "set_enabled", "name": "aegis · steam udp",
                           "enabled": False}
    assert prov.get_rule("Aegis · steam udp").enabled is False
    assert any("regra.toggle" in l and "desabilitada" in l
               for l in prov._audit_path.read_text(encoding="utf-8").splitlines())


def test_toggle_de_regra_do_so_recusada_sem_elevar(tmp_path):
    prov = _provider_com_regra_aegis()
    prov._audit_path = tmp_path / "audit.log"
    chamadas = []
    svc = _service(prov, chamadas)
    res = svc.set_enabled("regra do SO", False)
    assert res["ok"] is False and "sistema" in res["motivo"]
    assert chamadas == []  # nenhum UAC disparado


def test_runner_quebrado_e_auditado_sem_cair(tmp_path):
    prov = _provider_com_regra_aegis()
    prov._audit_path = tmp_path / "audit.log"
    def runner(req):
        raise RuntimeError("powershell sumiu")
    svc = ApplyService(prov, runner, AuditLog(prov._audit_path))
    res = svc.set_enabled("Aegis · steam udp", False)
    assert res["ok"] is False and "powershell sumiu" in res["motivo"]
