from __future__ import annotations

from typing import Any, Callable, Dict

from aegis.aiassist import RuleDraft
from aegis.audit import AuditLog
from aegis.firewall import IFirewallProvider, find_conflicts

Runner = Callable[[Dict[str, Any]], Dict[str, Any]]


class ApplyService:
    """Unico caminho para escrita no firewall. Toda saida daqui foi
    aprovada por humano (status 'aprovado' na fila) e passa pelo runner
    elevado; nada aqui decide sozinho."""

    def __init__(self, provider: IFirewallProvider, runner: Runner,
                 audit: AuditLog):
        self.provider = provider
        self.runner = runner
        self.audit = audit

    def apply(self, draft: RuleDraft, replace: bool = False) -> Dict[str, Any]:
        # Portao de propriedade: a camada COM marca built_in = nao-com-prefixo,
        # entao uma regra criada sem "Aegis " ficaria irremovivel pelo Aegis
        # depois. Recusa antes de qualquer contato com o sistema.
        if not draft.spec.name.startswith("Aegis "):
            self.audit.record("regra.recusada", draft.spec.name,
                              "nada alterado")
            return {"ok": False,
                    "motivo": "nome de regra Aegis deve comecar com 'Aegis ' "
                              "(prefixo de propriedade)"}
        rules = self.provider.list_rules()
        # conflito de NOME so e sobrevisivel com replace=True (decisao humana
        # explicita); conflito de porta/app bloqueia sempre, antes de elevar.
        # regra do sistema nunca some do portao, mesmo com replace
        conflicts = [c for c in find_conflicts(rules, draft.spec)
                     if c.name.lower() != draft.spec.name.lower()
                     or not replace or c.built_in]
        if conflicts:
            motivo = "conflito"
            self.audit.record("regra.bloqueada-por-conflito", draft.spec.name,
                              "nada alterado")
            return {"ok": False, "motivo": motivo,
                    "conflitos": [{"name": c.name, "built_in": c.built_in}
                                  for c in conflicts]}
        try:
            result = self.runner({"op": "add_rule", "spec": draft.spec.to_dict(),
                                  "draft_id": draft.draft_id,
                                  "replace": replace})
            ok = bool(result.get("ok"))
            verificada = ok and self.provider.get_rule(draft.spec.name) is not None
        except Exception as exc:
            # transporte (spawn/JSON) nao pode furar a promessa de todo desfecho auditado
            self.audit.record("regra.recusada", draft.spec.name,
                              f"erro interno: {exc}")
            return {"ok": False, "verificada": False,
                    "motivo": f"erro interno: {exc}"}
        motivo = result.get("motivo", "")
        if ok and not verificada:
            # o runner aceitou mas a releitura nao achou a regra: explique, nao vaze vazio
            motivo = "regra nao encontrada depois de aplicar (releitura falhou)"
        self.audit.record("regra.aplicada" if ok else "regra.recusada",
                          draft.spec.name,
                          "ok+verificado" if verificada else str(motivo or "falha"))
        return {"ok": ok, "verificada": verificada, "motivo": motivo}

    def remove(self, name: str) -> Dict[str, Any]:
        rule = self.provider.get_rule(name)
        if rule is None:
            self.audit.record("regra.remocao", name, "nao encontrada")
            return {"ok": False, "motivo": "regra nao encontrada"}
        if rule.built_in:
            self.audit.record("regra.remocao", name,
                              "recusada: regra do sistema, Aegis so mostra")
            return {"ok": False,
                    "motivo": "esta regra pertence ao sistema; o Aegis nao a edita em silencio"}
        try:
            result = self.runner({"op": "remove_rule", "name": name})
            runner_ok = bool(result.get("ok"))
            ainda_presente = self.provider.get_rule(name) is not None
            ok = runner_ok and not ainda_presente
        except Exception as exc:
            # transporte (spawn/JSON) nao pode furar a promessa de todo desfecho auditado
            self.audit.record("regra.remocao.falhou", name,
                              f"erro interno: {exc}")
            return {"ok": False, "motivo": f"erro interno: {exc}"}
        motivo = result.get("motivo", "")
        if runner_ok and ainda_presente:
            # o runner confirmou mas a regra segue la: explique, nao vaze vazio
            motivo = "regra ainda presente depois de remover (releitura falhou)"
        self.audit.record("regra.removida" if ok else "regra.remocao.falhou",
                          name, "ok" if ok else str(motivo or "falha"))
        return {"ok": ok, "motivo": motivo}
