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
