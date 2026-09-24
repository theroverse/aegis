from __future__ import annotations

from dataclasses import dataclass
from typing import List, Protocol


@dataclass
class Connection:
    pid: int
    process: str
    protocol: str
    local: str
    remote: str
    status: str


@dataclass
class BlockEvent:
    ts: str
    direction: str  # "in" | "out" | "" (desconhecida)
    protocol: str
    src: str
    dst: str
    port: str
    program: str = ""
    count: int = 1


class SourceUnavailable(Exception):
    """Fonte existe mas sabe que nao pode responder (ex.: log desativado)."""


class IConnectionSource(Protocol):
    """Contrato: implementacoes devem falhar apenas com SourceUnavailable
    ou OSError, e normalizar protocol para minusculas."""

    def connections(self) -> List[Connection]: ...


class IBlockEventSource(Protocol):
    """Contrato: implementacoes devem falhar apenas com SourceUnavailable
    ou OSError, e normalizar protocol para minusculas."""

    def new_events(self) -> List[BlockEvent]: ...


class MergedBlockSource:
    """Une fontes de bloqueio sem deixar uma cega derrubar as outras.
    Regression que este merge evita: o composite antigo somava as listas e a
    excecao do pfirewall.log subia DEPOIS de o event log ja ter consumido o
    lote — os eventos daquele ciclo desapareciam em silencio. Aqui, fonte
    indisponivel e registrada como cega, mas o que as vivas trouxerem chega
    ao monitor. So levanta SourceUnavailable quando TODAS estao cegas."""

    def __init__(self, sources):
        self._sources = list(sources)

    def new_events(self):
        events, cegas = [], []
        for s in self._sources:
            try:
                events.extend(s.new_events())
            except SourceUnavailable as exc:
                cegas.append(str(exc))
        if cegas and len(cegas) == len(self._sources):
            raise SourceUnavailable(" ; ".join(cegas))
        return events
