import sys
import types

from aegis.system.logstate import FirewallLogState, _BASE, _PERFIS


class _Chave:
    def __init__(self, valores, caminho=""):
        self.valores = valores
        self.caminho = caminho

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _WinregFake:
    """Registro na forma REAL da build 26200 (provado ao vivo): o log mora em
    <Perfil>\\Logging\\LogDroppedPackets; a chave do perfil NAO tem LogBlocked.
    Ler LogBlocked no perfil devolvia {} para sempre e o banner virava
    teimoso: log ativo no netsh, 'desativado' na GUI."""

    HKEY_LOCAL_MACHINE = "HKLM"

    def __init__(self, arvore):
        self._arvore = arvore

    def OpenKey(self, raiz, caminho):
        base = raiz.caminho if isinstance(raiz, _Chave) else ""
        cheio = f"{base}\\{caminho}" if base else caminho
        vals = self._arvore.get(cheio)
        if vals is None:
            raise OSError(2, "chave nao encontrada", cheio)
        return _Chave(vals, cheio)

    def QueryValueEx(self, chave, nome):
        if nome not in chave.valores:
            raise OSError(2, "valor nao encontrado", nome)
        return (chave.valores[nome], 4)


def _arvore_26200(valor_log=1):
    arvore = {_BASE: {}}
    for perfil in _PERFIS:
        arvore[f"{_BASE}\\{perfil}"] = {"EnableFirewall": 1}
        arvore[f"{_BASE}\\{perfil}\\Logging"] = {
            "LogDroppedPackets": valor_log,
            "LogSuccessfulConnections": 0,
            "LogFilePath": "C:\\WINDOWS\\system32\\LogFiles\\Firewall\\pfirewall.log",
        }
    return arvore


def test_le_logdroppedpackets_da_subchave_logging(monkeypatch):
    monkeypatch.setitem(sys.modules, "winreg", _WinregFake(_arvore_26200(1)))
    from aegis.system.logstate import _ler_logblocked_registry
    assert _ler_logblocked_registry() == {p: 1 for p in _PERFIS}


def test_logging_desligado_no_registro_devolve_zeros(monkeypatch):
    monkeypatch.setitem(sys.modules, "winreg", _WinregFake(_arvore_26200(0)))
    from aegis.system.logstate import _ler_logblocked_registry
    assert _ler_logblocked_registry() == {p: 0 for p in _PERFIS}


def test_sem_subchave_logging_nao_inventa_valor(monkeypatch):
    arvore = {_BASE: {}}
    for perfil in _PERFIS:
        arvore[f"{_BASE}\\{perfil}"] = {"EnableFirewall": 1}  # sem Logging
    monkeypatch.setitem(sys.modules, "winreg", _WinregFake(arvore))
    from aegis.system.logstate import _ler_logblocked_registry
    assert _ler_logblocked_registry() == {}


def test_um_perfil_com_logblocked_1_ja_ativa():
    # a verdade sobre o log mora no registro: ANY perfil com LogBlocked=1
    # significa log de bloqueios ativado — nao depende do arquivo existir.
    st = FirewallLogState(reader=lambda: {"DomainProfile": 0,
                                          "PublicProfile": 1,
                                          "StandardProfile": 0})
    assert st.enabled() is True


def test_todos_perfis_com_logblocked_0_desativado():
    st = FirewallLogState(reader=lambda: {"DomainProfile": 0,
                                          "PublicProfile": 0,
                                          "StandardProfile": 0})
    assert st.enabled() is False


def test_sem_leitura_possivel_declara_falso_conservador():
    # sem admin o registro pode recusar: o banner continua visivel e
    # honesto — nunca finge que o log esta ligado.
    def reader():
        raise OSError("acesso negado")
    assert FirewallLogState(reader=reader).enabled() is False


def test_dicionario_vazio_desativado():
    assert FirewallLogState(reader=lambda: {}).enabled() is False
