from __future__ import annotations

from typing import Callable, Optional

# HKLM ... FirewallPolicy\<perfil>\Logging -> LogDroppedPackets (DWORD).
# Leitura comum, sem admin: e a fonte da verdade sobre o log estar ATIVADO —
# a ausencia do pfirewall.log nao prova nada (o Windows so cria o arquivo na
# primeira linha registrada, nao quando a config e ligada). O caminho com a
# subchave 'Logging' e o nome LogDroppedPackets foram provados ao vivo na
# build 26200 contra `netsh advfirewall show allprofiles logging`: o valor
# LogBlocked direto no perfil (livro de politica/GPO) NAO existe la — le-lo
# devolvia {} para sempre e o banner de log ficava teimoso mesmo ativo.
_BASE = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
_PERFIS = ("DomainProfile", "PublicProfile", "StandardProfile")


def _ler_logblocked_registry() -> dict:
    import winreg  # import tardio: so o caminho real toca o sistema
    out = {}
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _BASE) as raiz:
        for perfil in _PERFIS:
            try:
                with winreg.OpenKey(raiz, perfil + r"\Logging") as k:
                    out[perfil] = int(winreg.QueryValueEx(k, "LogDroppedPackets")[0])
            except OSError:
                continue
    return out


class FirewallLogState:
    """True quando algum perfil tem LogBlocked=1. Sem leitura possivel do
    registro, declara False (conservador: o banner continua visivel e honesto
    — nunca finge que o log esta ligado)."""

    def __init__(self, reader: Optional[Callable[[], dict]] = None):
        self._reader = reader or _ler_logblocked_registry

    def enabled(self) -> bool:
        try:
            valores = self._reader()
        except OSError:
            return False
        return any(int(v) == 1 for v in valores.values())
