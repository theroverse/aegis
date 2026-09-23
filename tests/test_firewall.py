from aegis.firewall import RuleInfo, find_conflicts, ports_overlap
from aegis.models import RuleSpec

SPEC = RuleSpec(name="Aegis · Steam", direction="in", action="allow",
                protocol="udp", local_ports="3476-3481",
                program="C:\\Steam\\steam.exe")


def info(name, **kw):
    base = dict(name=name, direction="in", action="allow", protocol="udp",
                local_ports="3476-3481", profiles=("private",),
                enabled=True, program="C:\\Steam\\steam.exe", built_in=False)
    base.update(kw)
    return RuleInfo(**base)


def test_mesmo_nome_e_conflito():
    assert find_conflicts([info("Aegis · Steam")], SPEC) != []


def test_mesmo_app_mesma_faixa_mesma_direcao_e_conflito():
    assert find_conflicts([info("outra")], SPEC) != []


def test_direcao_diferente_nao_conflita():
    assert find_conflicts([info("outra", direction="out")], SPEC) == []


def test_outro_programa_nao_conflita():
    assert find_conflicts([info("outra", program="C:\\outro.exe")], SPEC) == []


def test_ports_overlap():
    assert ports_overlap("3476-3481", "3480")
    assert ports_overlap("*", "80")
    assert not ports_overlap("80", "443")
