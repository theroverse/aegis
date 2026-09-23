# Aegis — Escudo de Rede do Theroverse

O **Aegis** é o satélite de defesa da rede no Theroverse: um escudo
inteligente e transparente para o Windows Defender Firewall. Em vez de um
antivírus tradicional que apaga arquivos no susto sem sua permissão, o Aegis
monitora, explica e devolve a você o poder total de decisão.

## Filosofia (regras de ouro do Theroverse)

- **O dono do computador é você.** Toda escrita no firewall exige um clique
  humano consciente + confirmação do UAC. Não existe modo "auto".
- **Zero bloqueios cegos.** O Aegis alerta, explica o motivo em linguagem
  humana e propõe a ação — nunca aplica sozinho.
- **Privacidade local.** Nenhuma telemetria, nenhuma chamada de nuvem. O
  motor de IA que assistente opcional é fornecido pelo usuário (Thero/Zeus),
  consultado via arquivos de tarefa, como no Sentinel.
- **Portável e limpo.** Um único .exe, sem instalador, sem sujeira no sistema.

## O que ele faz (v0 planejada)

1. **Regras de firewall sob controle** — lista, cria e remove regras de
   portas/aplicativos via API nativa do Windows (leitura sem admin; escrita
   eleva só o helper pontual sob UAC).
2. **Tráfego ao vivo** — conexões ativas e eventos de bloqueio em tempo
   quase real (polling do event log + `pfirewall.log`), deduplicados e
   explicáveis.
3. **Assistente de IA para regras** — diante de um bloqueio, o Aegis monta um
   prompt com o que foi medido e recebe rascunhos de regra mínimos, que
   entram numa fila de **revisão humana** antes de tocar no sistema.
4. **Auditoria local** — toda ação (inclusive "nada alterado") fica num log
   append-only legível na própria interface.

## Estado atual

Repositório criado em 2026-09-23. Design v0 em aprovação
(`docs/superpowers/specs/` no monorepo pai, `theroverse/myscripts`); nenhum
código de motor foi escrito ainda.

## Layout planejado (convenção zeus-style)

```
aegis/
├── aegis.py            # entry fino: CLI e launch da GUI (pywebview)
├── src/aegis/          # motor Python puro, testável sem janela
│   └── system/         # única camada que conhece o Windows
├── gui/                # janela pywebview + web/ (HTML/CSS/JS)
├── scripts/            # helper privilegiado AegisApply
├── tests/              # pytest offline-first
└── build.ps1           # PyInstaller single-file
```

Identidade visual: campo grafite da casa (`#0B0C0E`) com primária
**azul-cobalto `#2563EB`** — distinta de Sentinel (vermelho), Athena
(crimson), Vector (magenta) e Genesis (ciano/violeta).

## Licença

MIT — veja [LICENSE](LICENSE).
