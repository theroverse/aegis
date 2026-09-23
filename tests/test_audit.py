from aegis.audit import AuditLog


def test_record_e_read_na_ordem(tmp_path):
    log = AuditLog(tmp_path / "audit.log")
    log.record("regra.aplicada", "Aegis · x", "ok+verificado")
    log.record("uac.cancelado", "ativar-log", "nada alterado")
    lines = log.read()
    assert len(lines) == 2
    # ":2" e o seculo do carimbo local ("2026-..."): o plano escreve "[:4]",
    # que so teria funcionado com um ano de dois digitos.
    assert "regra.aplicada" in lines[0] and lines[0][:2] == "20"
    assert lines[1].endswith("nada alterado")


def test_read_sem_arquivo_e_lista_vazia(tmp_path):
    assert AuditLog(tmp_path / "nao-existe.log").read() == []


def test_read_tail_so_as_ultimas_e_append_preserva(tmp_path):
    log = AuditLog(tmp_path / "audit.log")
    for i in range(5):
        log.record("acao", "alvo-%d" % i, "ok")
    tail = log.read(tail=2)
    assert len(tail) == 2 and "alvo-3" in tail[0] and "alvo-4" in tail[1]
    assert len(log.read()) == 5  # append-only: nada e reescrito


def test_record_sanitiza_quebras_de_linha(tmp_path):
    log = AuditLog(tmp_path / "audit.log")
    log.record("a", "b", "falha\nstack")
    lines = log.read()
    assert len(lines) == 1  # uma linha por registro, mesmo com \n no campo
    assert "falha / stack" in lines[0]
