import pytest

from aegis.models import CONFIDENCES, RuleSpec, SpecError, validate_ports


def test_validate_ports_aceita_item_e_faixa():
    assert validate_ports("6881") == ["6881"]
    assert validate_ports("3476-3481,6881") == ["3476-3481", "6881"]
    assert validate_ports("*") == ["*"]


@pytest.mark.parametrize("bad", ["", "0", "70000", "80-20", "abc", "*,80", "80,,90"])
def test_validate_ports_recusa_lixo(bad):
    with pytest.raises(ValueError):
        validate_ports(bad)


def test_spec_valida_enum_e_coleta_erros():
    spec = RuleSpec(
        name="Aegis · teste", direction="in", action="allow",
        protocol="tcp", local_ports="6881", profiles=("private",),
    )
    assert spec.to_dict()["local_ports"] == "6881"
    with pytest.raises(SpecError) as err:
        RuleSpec(name="x", direction="lado", action="talvez",
                 protocol="ipx", local_ports="6881")
    joined = " | ".join(err.value.errors)
    assert "direction" in joined and "action" in joined and "protocol" in joined


def test_from_dict_recusa_campo_desconhecido():
    with pytest.raises(SpecError) as err:
        RuleSpec.from_dict({
            "name": "n", "direction": "in", "action": "allow",
            "protocol": "tcp", "local_ports": "80", "evil": 1,
        })
    assert "campo desconhecido: evil" in " | ".join(err.value.errors)


def test_from_dict_to_dict_roundtrip():
    d = {
        "name": "n", "direction": "out", "action": "block",
        "protocol": "udp", "local_ports": "", "remote_ports": "*",
        "program": "C:\\x.exe", "profiles": ["public"], "enabled": False,
        "description": "desc",
    }
    assert RuleSpec.from_dict(d).to_dict() == d | {"profiles": ["public"]}


def test_confidences_sao_as_tres_da_casa():
    assert CONFIDENCES == ("baixa", "media", "alta")
