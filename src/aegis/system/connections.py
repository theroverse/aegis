from __future__ import annotations

import socket
from typing import Callable, List, Optional

from aegis.sources import Connection

# Rotulo: o engine guarda o status COMO o psutil da (traducao PT-BR e
# papel da GUI, Plano B). UDP sem status conta como LISTENING.
_KEEP = {"ESTABLISHED": "ESTABLISHED", "LISTENING": "LISTENING"}


def active_connections(proc_name: Optional[Callable[[int], str]] = None) -> List[Connection]:
    import psutil  # import tardio deliberado: motor portavel, so o sistema sabe

    def name_for(pid):
        if not pid:
            return "?"
        if proc_name is not None:
            return proc_name(pid)
        try:
            return psutil.Process(pid).name()
        except psutil.Error:
            return "?"

    out: List[Connection] = []
    for c in psutil.net_connections(kind="inet"):
        status = c.status or ""
        is_udp = c.type == socket.SOCK_DGRAM
        if not (status in _KEEP or (is_udp and status == "")):
            continue
        out.append(Connection(
            pid=c.pid or 0, process=name_for(c.pid),
            protocol="udp" if is_udp else "tcp",
            local=f"{c.laddr.ip}:{c.laddr.port}",
            remote=f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-",
            status=status or "LISTENING"))
    return out
