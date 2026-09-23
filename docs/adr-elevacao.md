# ADR — Arquitetura de elevação do Aegis v0

- **Status:** Aceita
- **Data:** 2026-09-23
- **Decisão-orig:** motor sem admin escreve via um único micro-helper
  privilegiado sob UAC visível.

## Contexto

O ethos do Aegis é ser **portável e limpo**: um único `.exe`, sem instalador,
sem serviço residente no sistema e sem telemetria. Isso conflita direto com a
realidade do Windows Defender Firewall: **criar ou remover uma regra exige
administração**, mas o motor (a UI, o monitor, a fila de revisão) deve rodar
**sem privilégios**, para nunca ter poder de escrita silenciosa.

Rejeitamos as alternativas clássicas:

- **Serviço/agendador residente elevado** — contradiz "portável, sem sujeira"
  e cria um canal de escrita sempre aberto (superfície de ataque).
- **Reiniciar o app inteiro como admin** — dá poder de escrita contínuo ao
  processo que o humano não pode auditar clique a clique.
- **Escrita direta com `runas` no motor** — acopla o motor core ao Windows e
  some com a fronteira de portabilidade.

## Decisão

Toda **leitura** (listar regras, conexões ativas, log de bloqueios) acontece
no processo do motor, **sem admin**. Toda **escrita** acontece **única e
exclusivamente** por meio de um micro-helper privilegiado,
`AegisApply.exe` (empacotado de `scripts/aegis_apply.py`), disparado **uma vez
por escrita** sob **UAC visível**:

```
powershell -NoProfile -NonInteractive -Command "Start-Process \
  -FilePath 'AegisApply.exe' -ArgumentList '<req>','<res>' \
  -Verb RunAs -Wait"
```

O helper usa o **mesmo `ComFirewallProvider`** da leitura (COM
`HNetCfg.FwPolicy2`), então o que o humano revisa é exatamente o que é
escrito. O protocolo entre motor e helper é **JSON por arquivos** no
diretório de estado `.aegis/`:

1. Motor escreve `req-<id>.json` com a operação (`add_rule` / `remove_rule`,
   `replace`).
2. `_spawn` dispara o helper elevado com `-Verb RunAs -Wait` e **bloqueia**
   até o processo elevado terminar (cap de **120 s**).
3. Helper aplica e escreve `res-<id>.json` (`{"ok": true}` ou
   `{"ok": false, "motivo": "..."}`).
4. Motor lê o result e faz a **verificação por releitura**.

Se o humano **cancela ou nega o UAC**, nenhum processo elevado nasce e
nenhum `res-*.json` é escrito: o motor rotula o desfecho literalmente como
**"UAC cancelado — nada tocou o sistema"**. Os arquivos `req-*.json` /
`res-*.json` ficam no `.aegis/` como **trilha forense** e **não são apagados**
deliberadamente.

## Consequências

- **Cancelamento é seguro por construção.** Negar o UAC garante que o sistema
  não foi tocado — não há escrita parcial possível. Isso foi validado ao vivo
  na máquina (2026-09-23): ao recusar o prompt, nenhum `res-*.json` surgiu e a
  regra não apareceu no firewall.
- **Janela não-atômica no `replace`.** `replace` faz `remove` + `add`, que
  **não é atômico**: se o `add` falhar depois do `remove`, a regra antiga está
  perdida. O helper detecta esse caso e grava o motivo explícito — *"regra
  antiga removida pelo replace e não recriada"* — no result, em vez de
  silenciar.
- **Arquivos forenses se acumulam.** Cada escrita deixa um par `req/res`; a
  **v0 não rotaciona**. A rotação/limpeza fica para a v1 (decisão consciente).
- **Cap de 120 s.** Um helper travado não pode pendurar o motor: o `_spawn`
  tem `timeout=120`, e qualquer falha de spawn/timeout volta como
  `motivo` sem explodir o `ApplyService`.
- **A GUI deve chamar fora da thread principal.** Como `Start-Process -Wait`
  bloqueia até o fim do UAC + execução, a camada de interface precisa disparar
  a escrita numa thread de trabalho para não congelar a janela.
- **Portabilidade preservada.** O `ElevatedRunner` só conhece `powershell` e
  arquivos JSON; o motor core continua sem Windows, com a fronteira vigiada
  por `tests/test_boundary.py`.
