from aegis.system.logstate import FirewallLogState


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
