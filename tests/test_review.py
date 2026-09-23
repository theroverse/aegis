import pytest

from aegis.aiassist import RuleDraft
from aegis.models import RuleSpec
from aegis.review import DraftStore
from aegis.settings import write_json_atomic

SPEC = RuleSpec(name="Aegis · x", direction="in", action="allow",
                protocol="tcp", local_ports="80", program="p")


def draft():
    return RuleDraft(spec=SPEC, rationale="r", confidence="media")


def test_persistencia_e_id_seqencial(tmp_path):
    s = DraftStore(tmp_path / "drafts.json")
    d1 = s.add(draft()); d2 = s.add(draft())
    assert (d1.draft_id, d2.draft_id) == ("d001", "d002")
    again = DraftStore(tmp_path / "drafts.json")
    assert [x.draft_id for x in again.all()] == ["d001", "d002"]


def test_transicoes_validas(tmp_path):
    s = DraftStore(tmp_path / "drafts.json")
    d = s.add(draft())
    s.set_status(d.draft_id, "aprovado")
    s.set_status(d.draft_id, "aplicado")
    assert s.get(d.draft_id).status == "aplicado"


def test_transicao_ilicita_morre(tmp_path):
    s = DraftStore(tmp_path / "drafts.json")
    d = s.add(draft())
    s.set_status(d.draft_id, "rejeitado")
    with pytest.raises(ValueError):
        s.set_status(d.draft_id, "aprovado")


def test_filtragem_por_status(tmp_path):
    s = DraftStore(tmp_path / "drafts.json")
    a, b = s.add(draft()), s.add(draft())
    s.set_status(a.draft_id, "rejeitado")
    assert [x.draft_id for x in s.all("pendente")] == ["d002"]


def test_recarrega_preserva_status_e_campos(tmp_path):
    s = DraftStore(tmp_path / "drafts.json")
    d = s.add(draft())
    s.set_status(d.draft_id, "aprovado")
    again = DraftStore(tmp_path / "drafts.json")
    r = again.get(d.draft_id)
    assert r.status == "aprovado"
    assert r.rationale == "r"
    assert r.confidence == "media"


def test_get_inexistente_keyerror(tmp_path):
    s = DraftStore(tmp_path / "drafts.json")
    with pytest.raises(KeyError):
        s.get("d999")


def test_arquivo_com_entradas_podres_sobrevive(tmp_path):
    path = tmp_path / "drafts.json"
    base = DraftStore(path)
    bom = base._to_dict(base.add(draft()))
    write_json_atomic(path, {"counter": 5, "drafts": [42, {"sem": "campos"}, bom]})
    s = DraftStore(path)
    assert [x.draft_id for x in s.all()] == ["d001"]
    # id novo fica acima do counter declarado: sem colisao nem reuso
    assert s.add(draft()).draft_id == "d006"


def test_entrada_boa_apos_podre_mantem_counter_minimo(tmp_path):
    path = tmp_path / "drafts.json"
    base = DraftStore(path)
    bom = base._to_dict(base.add(draft()))
    bom["draft_id"] = "d050"
    write_json_atomic(path, {"counter": "abc", "drafts": [42, bom]})
    s = DraftStore(path)
    assert s.add(draft()).draft_id == "d051"
