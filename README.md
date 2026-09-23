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

## O que ele faz (v0)

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

**v0 do motor implementada** em `src/aegis` (regra, monitor, assistente de IA,
fila de revisão, aplicação elevada, fontes de bloqueio e provedor COM), com
CLI funcional e suíte `pytest` offline verde. A GUI (pywebview) e o helper
empacotado `AegisApply.exe` chegam na próxima fase. O comportamento de
elevação está registrado em
[`docs/adr-elevacao.md`](docs/adr-elevacao.md).

## Uso (v0 motor)

Tudo passa pelo entry fino `aegis.py`. Os comandos abaixo rodam o motor real;
acrescente `--offline` para o smoke determinístico.

```bash
# Smoke em QUALQUER SO — nunca toca o firewall real (ver --offline abaixo)
python aegis.py --offline status

# Leitura do estado ao vivo (sem admin)
python aegis.py status
python aegis.py rules

# Assistente de IA: devolve o PROMPT em texto (o motor de IA é seu)
python aegis.py ask-ai --program "C:\app\servidor.exe" --port 8080 \
    --direction in --protocol tcp

# Entrada da resposta JSON da IA -> vira rascunho pendente na fila de revisão
python aegis.py ingest resposta_ia.json

# Aprova um rascunho e dispara a escrita elevada (UAC visível)
python aegis.py approve d001
python aegis.py approve d001 --replace   # substitui regra de mesmo nome

# Auditoria local (append-only)
python aegis.py audit
```

- `status` → `regras`, `conexoes`, `bloqueios_no_anel`, `estado_bloqueios` e
  `revisoes_pendentes`.
- `rules` → despeja todas as regras como JSON (uma varredura pode ter centenas
  de itens; redirecione para um arquivo se for comparar).
- `ask-ai` → imprime apenas o **prompt montado**; ele não chama IA nenhuma.
  Você roda o prompt no seu assistente (Thero/Zeus), salva a resposta JSON e a
  injeta com `ingest`.
- `--offline` → troca o provedor COM, as conexões e a fonte de bloqueios pelos
  **fakes de `tests/fakes.py`**. Serve para smoke/CI em Linux/macOS: **nenhum
  comando offline toca o firewall nem o sistema**, e o runner elevado devolve
  `{"ok": false, "motivo": "offline"}`.

## Contrato de elevação

- **Leitura sempre sem admin.** Listar regras, conexões ativas e o log de
  bloqueios não exige privilégio algum.
- **Escrita única e exclusivamente via micro-helper.** Toda mudança no firewall
  passa pelo `AegisApply`, disparado sob **UAC visível** com
  `Start-Process -Verb RunAs -Wait`. Não existe caminho de escrita silenciosa
  no motor.
- **Cancelar o UAC = nada tocou o sistema.** Se você negar ou cancelar o
  prompt, nenhum processo elevado nasce, nenhum resultado é escrito e o motor
  reporta literalmente *"UAC cancelado — nada tocou o sistema"*.
- **Trilha forense.** Os arquivos `req-*.json` / `res-*.json` trocados com o
  helper ficam no diretório de estado `.aegis/` e **não são apagados** — são a
  prova auditável do que foi pedido e do que voltou.

## Fronteira de portabilidade

O **motor** (`src/aegis`, tudo que está **fora de `system/`**) **não conhece o
Windows**: nenhum `comtypes`, `winreg`, `ctypes` ou `psutil`. Toda a sujeira
específica de plataforma vive isolada em `src/aegis/system/` e nos
`scripts/`. O cão de guarda dessa fronteira é `tests/test_boundary.py`, que
falha a suíte se qualquer import proibido vazar para o core — assim o motor
continua testável offline em qualquer SO.

## Fonte de bloqueios na v0

Achado validado na máquina (Windows 11, 2026-09-23) que precisa ficar
documentado, porque muda o que a v0 consegue medir:

- O canal **"Microsoft-Windows-Windows Firewall With Advanced
  Security/Firewall" NÃO emite eventos de packet-drop.** Os IDs que ele tem
  (2004–2007 e vizinhos) são de **mudança de regra/config/perfil**, não de
  tráfego bloqueado. Os drops reais do WFP vão para o **Security log**
  (eventos 5152/5153), que só preenche com **política de auditoria ativa**.
- Por isso o default `firewall.bloqueios_event_ids = []` — sem filtro de IDs,
  a fonte de event log fica em branco de propósito (prova de que o canal não
  serve para drops).
- A **fonte primária de bloqueios da v0 é o `pfirewall.log`**, que por padrão
  vem **DESATIVADO**. Habilitá-lo exige um comando elevado; na v0 ele aparece
  como `estado_bloqueios: ["indisponivel", ...]` até você ligar o log. A UI com
  toggle "ativar log de bloqueios" chega no **Plano B**.

Para habilitar o log **manualmente** apenas para testar (passo elevado, não
executado por padrão):

```powershell
sc.exe start mpssvc
Set-NetFirewallProfile -LogFileName C:\Windows\System32\LogFiles\Firewall\pfirewall.log -LogAllowed 0 -LogBlocked 1
```

## Fluxo IA → revisão → UAC

1. `ask-ai` monta o **prompt** com o que foi medido (programa, direção,
   protocolo, porta, contexto). O motor de IA é **seu** — o Aegis não chama
   nuvem nenhuma.
2. Você roda o prompt no assistente e salva a **resposta JSON**.
3. `ingest` faz o parse, **valida estritamente** cada rascunho e coloca tudo
   na **fila de revisão** como pendente (nada toca o sistema ainda).
4. Um **humano aprova** (`approve`), o que dispara uma única escrita elevada
   sob UAC visível.
5. Após aplicar, o motor **verifica por releitura** que a regra está de fato
   lá antes de marcar como aplicada.

Toda regra criada pelo Aegis usa o **prefixo de propriedade `"Aegis "`** — é o
que distingue uma regra sua de uma regra do sistema (`built_in`), e o portão
de escrita recusa qualquer nome sem esse prefixo. Regras do sistema nunca são
editadas em silêncio.

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
