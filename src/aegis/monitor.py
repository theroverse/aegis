from __future__ import annotations

import threading
from collections import deque
from dataclasses import replace
from typing import Callable, List, Optional

from aegis.sources import (BlockEvent, IBlockEventSource, IConnectionSource,
                           SourceUnavailable)


class Monitor:
    """ Feed ao vivo: conecta fontes declaradas, dedupa por janela e
    limita o historico num anel. Nunca escreve no sistema."""

    def __init__(self, conn_source: IConnectionSource,
                 block_source: IBlockEventSource,
                 clock: Callable[[], float],
                 window: float = 60.0, ring_size: int = 500):
        self._conns = conn_source
        self._blocks = block_source
        self._clock = clock
        self._window = window
        self._seen: dict = {}
        self._ring: deque = deque(maxlen=ring_size)
        self.blocked_state = ("ok", "")
        self.conn_state = ("ok", "")
        self.connections: List = []
        self._lock = threading.Lock()

    def observe(self, ev: BlockEvent) -> Optional[BlockEvent]:
        key = (ev.program.lower(), ev.protocol, ev.port, ev.direction)
        now = self._clock()
        hit = self._seen.get(key)
        if hit and hit[0] > now:
            # mesmo evento visto ha <window s: acumula no objeto que ja
            # esta no anel (referencia viva) em vez de poluir o feed
            held = hit[1]
            held.count += 1
            return None
        fresh = replace(ev, count=1)
        self._seen[key] = (now + self._window, fresh)
        return fresh

    def poll_blocked(self) -> None:
        try:
            events = self._blocks.new_events()
        except SourceUnavailable as exc:
            self.blocked_state = ("indisponivel", str(exc))
            return
        except OSError as exc:  # fonte quebrou: tambem declara, nunca mude
            self.blocked_state = ("erro", str(exc))
            return
        self.blocked_state = ("ok", "")
        with self._lock:
            # poda a memória de chaves vencidas: senao o _seen cresceria
            # para sempre num escudo que roda o dia inteiro.
            now = self._clock()
            self._seen = {k: v for k, v in self._seen.items() if v[0] > now}
            for ev in events:
                fresh = self.observe(ev)
                if fresh is not None:
                    self._ring.append(fresh)

    def poll_connections(self) -> None:
        # Estado proprio, espelho do bloqueio: uma quebra no psutil nao pode
        # tingir estado_bloqueios (e vice-versa). Fonte declaradamente ausente
        # (SourceUnavailable) diz "indisponivel"; o resto e "erro".
        try:
            self.connections = self._conns.connections()
        except SourceUnavailable as exc:
            self.conn_state = ("indisponivel", str(exc))
            return
        except Exception as exc:
            self.conn_state = ("erro", str(exc))
            return
        self.conn_state = ("ok", "")

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "conexoes": list(self.connections),
                "bloqueios": list(self._ring)[::-1],
                "estado_bloqueios": self.blocked_state,
                "estado_conexoes": self.conn_state,
            }

    def loop(self, stop: threading.Event, sleep, conn_s: float,
             block_s: float) -> None:
        """Ultimo recurso: fonte que quebra declara erro e o monitor
        continua vivo. relogio monotonic nao tem epoca: primeira.poll
        de bloqueios nao espera block_s."""
        last = self._clock() - block_s
        while not stop.is_set():
            try:
                now = self._clock()
                if now - last >= block_s:
                    self.poll_blocked()
                    last = now
                self.poll_connections()
            except Exception as exc:
                # qualquer Exception (ex.: ValueError de linha malformada)
                # vira estado declarado; a thread nunca morre em silencio.
                self.blocked_state = ("erro", str(exc))
            sleep(conn_s)
