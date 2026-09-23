from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List

from aegis.models import CONFIDENCES, RuleSpec, SpecError

RULE_PROMPT = r"""
Voce e o conselheiro de regras do Aegis, satellite de defesa de rede do
Theroverse. Um evento de rede precisa virar proposta de regra do Windows
Defender Firewall. Regras de conduta (filosofia do Theroverse):

- O usuario e o dono da maquina: voce PROPoe, humano dispoe. Nada aqui sera
  aplicado sem revisao humana explicita + confirmacao UAC.
- Minimo privilegio SEMPRE: porta especifica (ou faixa minima) em vez de
  "liberar o app inteiro"; o perfil de rede mais restrito que resolve o caso;
  direction e action conforme o evento medido.
- Se falta informacao para uma regra minima segura, diga isso no rationale e
  marque confidence "baixa" — nao chute portas extras.
- Responda em portugues do Brasil.

Contexto MEDIDO localmente (nao inventado):
- programa: {program}
- evento: direcao {direction}, protocolo {protocol}, porta {port}
- origem do pedido: {origin}
- perfil atual detectado: {profile}
- regras existentes que ja tocam neste programa:
{existing}

Formato da resposta: EXATAMENTE um array JSON com no maximo {max_regras}
elementos, sem cerca de codigo e sem prosa antes ou depois. Cada elemento e
um objeto JSON valido (sem comentarios), com este aspecto:
{{
  "rule": {{
    "name": "Aegis · <app> — <papel da porta>",
    "direction": "in",
    "action": "allow",
    "protocol": "tcp",
    "local_ports": "6881",
    "remote_ports": "",
    "program": "C:\\caminho\\absoluto\\medido.exe",
    "profiles": ["private"],
    "enabled": true,
    "description": "por que esta regra existe"
  }},
  "rationale": "o mecanismo: por que estas portas, nao outras",
  "confidence": "media",
  "checked": "o que foi verificado de fato (arquivo de config, docs) e o que NAO foi"
}}

O objeto "rule" (RuleSpec) leva exatamente estas chaves, nenhuma a mais.
Valores permitidos (escolha UM por campo, sem "|"): direction "in" ou "out";
action "allow" ou "block"; protocol "tcp", "udp" ou "any"; local_ports e
remote_ports aceitam uma porta ("6881"), uma faixa ("3476-3481") ou string
vazia quando nao se aplica; profiles e um array com um ou mais de "private",
"domain", "public"; confidence e "baixa", "media" ou "alta".
"""


class AiResponseError(ValueError):
    def __init__(self, errors: List[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


@dataclass
class RuleDraft:
    spec: RuleSpec
    rationale: str
    confidence: str
    checked: str = ""
    origin: str = "IA"
    status: str = "pendente"
    draft_id: str = ""


def build_prompt(ctx: Dict[str, Any], max_regras: int = 3) -> str:
    existing = ctx.get("existing") or ["(nenhuma)"]
    return RULE_PROMPT.format(
        program=ctx["program"], direction=ctx["direction"],
        protocol=ctx["protocol"], port=ctx["port"], origin=ctx["origin"],
        profile=ctx.get("profile", "?"),
        existing="\n".join(f"  - {r}" for r in existing),
        max_regras=max_regras)


def parse_drafts(text: str) -> List[RuleDraft]:
    try:
        payload = json.loads(text)
    except ValueError as exc:
        raise AiResponseError([f"JSON invalido: {exc}"])
    if not isinstance(payload, list) or not payload:
        raise AiResponseError(["esperado array JSON com 1+ itens"])
    drafts: List[RuleDraft] = []
    errors: List[str] = []
    for i, item in enumerate(payload):
        if not isinstance(item, dict) or not {"rule", "rationale", "confidence"} <= set(item):
            errors.append(f"item {i}: faltam rule/rationale/confidence")
            continue
        try:
            spec = RuleSpec.from_dict(item["rule"])
        except SpecError as exc:
            errors.append(f"item {i}: spec — {exc}")
            continue
        if item["confidence"] not in CONFIDENCES:
            errors.append(f"item {i}: confidence deve ser uma de {CONFIDENCES}")
            continue
        drafts.append(RuleDraft(spec=spec, rationale=str(item["rationale"]),
                                confidence=item["confidence"],
                                checked=str(item.get("checked", ""))))
    if errors:
        raise AiResponseError(errors)
    return drafts
