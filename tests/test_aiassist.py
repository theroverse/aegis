import pytest

from aegis.aiassist import (AiResponseError, RuleDraft, build_prompt,
                            parse_drafts)
from aegis.models import SpecError

GOOD = """[
  {"rule": {"name": "Aegis · qBittorrent escuta", "direction": "in",
            "action": "allow", "protocol": "tcp", "local_ports": "6881",
            "remote_ports": "", "program": "C:\\\\q\\\\qbittorrent.exe",
            "profiles": ["private"], "enabled": true, "description": ""},
   "rationale": "porta padrao de escuta do app",
   "confidence": "media",
   "checked": "confirmei na config interna do app"}
]"""


def test_build_prompt_contem_o_medido_e_a_ordem():
    prompt = build_prompt({
        "program": r"C:\q\qbittorrent.exe", "direction": "in",
        "protocol": "tcp", "port": "6881", "origin": "bloqueio observado",
        "profile": "private",
        "existing": ["Aegis · outra (tcp 9999 in)"],
    }, max_regras=3)
    assert r"C:\q\qbittorrent.exe" in prompt
    assert "6881" in prompt and "array JSON" in prompt
    assert "EXATAMENTE" in prompt


def test_parse_drafts_ok():
    drafts = parse_drafts(GOOD)
    assert len(drafts) == 1
    d = drafts[0]
    assert isinstance(d, RuleDraft) and d.origin == "IA" and d.status == "pendente"
    assert d.spec.profiles == ("private",)
    assert d.confidence == "media"


@pytest.mark.parametrize("bad", [
    "não é json",
    '{"rule": {}}',                       # objeto, nao array
    "[]",                                  # vazio
    '[{"rationale": "sem rule"}]',        # falta campo obrigatorio
    '[{"rule": {"name": "x"}, "rationale": "r", "confidence": "alta"}]',  # spec incompleta
    ('[{"rule": {"name": "x", "direction": "in", "action": "allow",'
     ' "protocol": "tcp", "local_ports": "80", "remote_ports": "",'
     ' "program": "p", "profiles": ["private"], "enabled": true,'
     ' "description": "", "hax": 1}, "rationale": "r", "confidence": "alta"}]'),
    '[{"rule": {"name": "x", "direction": "in", "action": "allow",'
    ' "protocol": "tcp", "local_ports": "80", "remote_ports": "",'
    ' "program": "p", "profiles": ["private"], "enabled": true,'
    ' "description": ""}, "rationale": "r", "confidence": "total"}]',
])
def test_parse_recusa(bad):
    with pytest.raises(AiResponseError):
        parse_drafts(bad)


def test_erro_aponta_indice_do_item_ruim():
    with pytest.raises(AiResponseError) as exc:
        parse_drafts('[{"rule": {"name": "ok", "direction": "in",'
                     ' "action": "allow", "protocol": "tcp", "local_ports": "80",'
                     ' "remote_ports": "", "program": "p", "profiles": ["private"],'
                     ' "enabled": true, "description": ""}, "rationale": "r",'
                     ' "confidence": "alta"}, {"rationale": "so"}]')
    assert any("item 1" in e for e in exc.value.errors)
