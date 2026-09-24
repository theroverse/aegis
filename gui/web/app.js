/* Aegis — laço vivo sobre window.aegis_api. Regra da casa: objetos complexos
   atravessam a ponte como string JSON (JSON.stringify), primitivos passam direto.
   Toda falha vira toast LITERAL — nada de estado mudo. */
"use strict";
const $ = (id) => document.getElementById(id);
let perfilAtivo = "", buscaAtiva = "", timer = null;

function el(tag, cls, html) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (html !== undefined) e.innerHTML = html;
  return e;
}
function esc(s) {
  return String(s ?? "").replace(/[&<>"]/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
function aegisApi() {
  // pywebview 6 publica TUDO sob window.pywebview.api; o namespace aegis_api
  // vem do wrapper _Ponte no python (atributo publico -> nome pontado).
  return (window.pywebview && window.pywebview.api
          && window.pywebview.api.aegis_api) || null;
}
async function api(nome, ...args) {
  const ponte = aegisApi();
  if (!ponte || !ponte[nome]) {
    throw new Error("ponte aegis_api indisponivel");
  }
  return await ponte[nome](...args);
}
function toast(msg, tipo = "ok", ms = 4200) {
  const t = $("toast");
  t.textContent = msg;
  t.className = "toast " + tipo;
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.hidden = true; }, ms);
}
function modal(titulo, corpo, acoes) {
  $("mTitle").textContent = titulo;
  const b = $("mBody"); b.replaceChildren(); b.appendChild(corpo);
  const a = $("mActions"); a.replaceChildren();
  (acoes || []).forEach(([rotulo, cls, fn]) => {
    const btn = el("button", "btn " + cls, rotulo);
    btn.onclick = async () => { fechar(); await fn(); renderTudo(); };
    a.appendChild(btn);
  });
  $("overlay").hidden = false;
}
function fechar() { $("overlay").hidden = true; }
$("overlay").addEventListener("click", (e) => { if (e.target === $("overlay")) fechar(); });

/* ---------- navegacao ---------- */
document.querySelectorAll(".navitem").forEach(n => {
  n.onclick = () => {
    document.querySelectorAll(".navitem").forEach(x => x.classList.remove("active"));
    n.classList.add("active");
    document.querySelectorAll(".page").forEach(p => p.classList.remove("show"));
    $(n.dataset.p).classList.add("show");
    if (n.dataset.p === "regras") renderRegras();
    if (n.dataset.p === "revisao") renderRevisao();
    if (n.dataset.p === "transp") renderAudit();
  };
});
function irPara(p) { document.querySelector(`.navitem[data-p="${p}"]`).click(); }

/* ---------- painel ---------- */
const TRAD = { ESTABLISHED: "ESTABELECIDO", LISTENING: "ESCUTANDO" };
async function renderPainel() {
  let s;
  try { s = await api("status"); } catch (e) {
    $("footMotor").textContent = "indisponivel";
    $("footMotor").className = "";
    toast("motor indisponivel: " + e, "err");
    return;
  }
  $("footMotor").textContent = "ativo"; $("footMotor").className = "ok";
  $("stConexoes").textContent = s.conexoes.length;
  $("stBloqueios").textContent = s.bloqueios.length;
  $("stAegis").innerHTML = s.regras_aegis + ' <small>de ' + s.regras_total + " totais</small>";
  const badge = s.revisoes_pendentes.length;
  $("badgeRev").hidden = badge === 0;
  $("badgeRev").textContent = badge;

  chipEstado("chipConn", s.estado_conexoes, "conexões", "2s");
  chipEstado("chipLog", s.estado_bloqueios, "log de bloqueios", "5s");
  const aviso = $("logNotice");
  if (s.estado_bloqueios.estado !== "ok") {
    aviso.hidden = false;
    $("logNoticeTxt").innerHTML =
      "O <b>log de bloqueios do firewall</b> está desativado — sem ele eu vejo as " +
      "conexões, mas não os pacotes barrados. <b>Nada muda sem você decidir:</b> " +
      "ativar escreve uma configuração do log (requer UAC). <span style='color:var(--muted)'>" +
      "(" + esc(s.estado_bloqueios.detalhe) + ")</span>";
  } else { aviso.hidden = true; }

  const tc = $("tbConexoes"); tc.replaceChildren();
  if (!s.conexoes.length) tc.appendChild(el("tr")).appendChild(el("td", "empty", "sem conexões vivas"));
  s.conexoes.slice(0, 60).forEach(c => {
    const tr = el("tr");
    const ouv = c.status === "LISTENING";
    tr.appendChild(el("td", "proc", esc(c.process) + ' <span style="color:var(--muted)">· ' + esc(c.pid) + "</span>"));
    tr.appendChild(el("td", "", esc(ouv ? c.local : c.remote)));
    tr.appendChild(el("td", "", esc(c.protocol.toUpperCase())));
    tr.appendChild(el("td", "", `<span class="st ${ouv ? "ouv" : "esc"}">${TRAD[c.status] || esc(c.status)}</span>`));
    tc.appendChild(tr);
  });

  const fb = $("feedBloqueios"); fb.replaceChildren();
  $("blockSrc").textContent = "fonte: event log + pfirewall.log · 5s";
  if (!s.bloqueios.length) fb.appendChild(el("div", "empty", "nenhum bloqueio no anel — lembre-se do log desativado"));
  s.bloqueios.slice(0, 40).forEach(b => {
    const linha = el("div", "ev");
    const nome = b.program ? b.program.split("\\").pop() : (b.src !== "-" ? b.src : "origem desconhecida");
    const dirTxt = b.direction === "in" ? "entrada" : (b.direction === "out" ? "saída" : "direção desconhecida");
    linha.appendChild(el("div", "ico " + (b.direction === "out" ? "out" : "in"),
                         b.direction === "out" ? "↑" : "↓"));
    linha.appendChild(el("div", "meta",
      `<b>${esc(nome)} — ${esc(b.protocol.toUpperCase())} ${esc(b.port || "?")} ${b.direction === "out" ? "bloqueada na saída" : "negada na entrada"}</b>` +
      `<span>${esc(dirTxt)} · ${esc(b.ts)}${b.dst && b.dst !== "-" ? " · " + esc(b.dst) : ""}</span>`));
    linha.appendChild(el("span", "cnt", "×" + b.count));
    const btn = el("button", "btn primary", "Entender / liberar");
    btn.onclick = () => entender(b, nome);
    linha.appendChild(btn);
    fb.appendChild(linha);
  });
}
function chipEstado(id, est, rotulo, cadencia) {
  const c = $(id);
  c.className = "chip " + (est.estado === "ok" ? "on" : "warn");
  c.textContent = `${rotulo} · ${est.estado === "ok" ? "ativo · " + cadencia : est.estado}`;
  c.title = est.detalhe || "";
}

/* ---------- fluxo IA em arquivo ---------- */
async function entender(bloco, nome) {
  let res;
  try { res = await api("understand", JSON.stringify(bloco)); }
  catch (e) { toast("falha ao montar prompt: " + e, "err"); return; }
  const corpo = el("div");
  corpo.appendChild(el("p", "",
    `<span style="font-size:12px;color:var(--muted)">Prompt com o que foi <b>medido</b> (executável, porta, direção, regras do app). Copie para o seu motor de IA (Thero/Zeus). Arquivo gravado em:</span><div class="linha-escrita">${esc(res.path)}</div>`));
  const ta = el("textarea", "form"); ta.value = res.prompt; ta.rows = 10;
  corpo.appendChild(ta);
  corpo.appendChild(el("label", "", '<label class="campo">Resposta da IA (array JSON de rascunhos — nada é aplicado daqui)</label>'));
  const ans = el("textarea", "form"); ans.rows = 6; ans.placeholder = '[{"rule":{...},"rationale":"...","confidence":"alta|media|baixa"}]';
  corpo.appendChild(ans);
  modal("Entender / liberar — " + nome, corpo, [
    ["Copiar prompt", "ghost", async () => { await navigator.clipboard.writeText(res.prompt).catch(()=>{}); toast("prompt copiado"); }],
    ["Ingerir resposta", "primary", async () => {
      const t = ans.value.trim();
      if (!t) { toast("cole a resposta da IA antes de ingerir", "warn"); return; }
      const r = await api("ingest_text", t);
      if (r.ok) { toast(`rascunho(s) na fila de revisão: ${r.ids.join(", ")}`); irPara("revisao"); }
      else toast("rejeitado pela validação: " + r.motivo, "err", 9000);
    }],
  ]);
}

/* ---------- regras ---------- */
$("qRegras").addEventListener("input", (e) => { buscaAtiva = e.target.value; renderRegras(); });
document.querySelectorAll("#segPerfil b").forEach(b => {
  b.onclick = () => {
    document.querySelectorAll("#segPerfil b").forEach(x => x.classList.remove("on"));
    b.classList.add("on"); perfilAtivo = b.dataset.pf; renderRegras();
  };
});
async function renderRegras() {
  let rs;
  try { rs = await api("rules", buscaAtiva, perfilAtivo); }
  catch (e) { toast("falha ao listar regras: " + e, "err"); return; }
  const tb = $("tbRegras"); tb.replaceChildren();
  if (!rs.length) tb.appendChild(el("tr")).appendChild(el("td", "empty", "nada para o filtro atual"));
  rs.slice(0, 300).forEach(r => {
    const tr = el("tr");
    const cel0 = el("td");
    if (r.aegis) {
      const tog = el("span", "tog" + (r.enabled ? "" : " off"));
      tog.onclick = () => toggle(r);
      cel0.appendChild(tog);
    } else { cel0.textContent = r.enabled ? "•" : "·"; cel0.style.color = "var(--muted)"; }
    tr.appendChild(cel0);
    tr.appendChild(el("td", "regraname", esc(r.name) +
      ` <span class="tag ${r.action === "allow" ? "allow" : "deny"}">${r.action === "allow" ? "PERMITIR" : "NEGAR"}</span>`));
    tr.appendChild(el("td", "", esc(r.action)));
    tr.appendChild(el("td", "", esc(r.protocol.toUpperCase()) + " " + esc(r.local_ports)));
    tr.appendChild(el("td", "", (r.profiles || []).map(p =>
      `<span class="tag ${p === "public" ? "pub" : "priv"}">${esc(p.toUpperCase())}</span>`).join(" ")));
    tr.appendChild(el("td", "", r.aegis ? '<span class="tag pub">AEGIS</span>'
      : '<span style="font-size:9.5px;color:#4A5260;font-family:var(--mono)">SO</span>'));
    const acts = el("td", "acts");
    if (r.aegis) {
      const rm = el("span", "mini", "remover"); rm.onclick = () => remover(r); acts.appendChild(rm);
    } else {
      acts.appendChild(el("span", "mini", "só leitura"));
    }
    tr.appendChild(acts);
    tb.appendChild(tr);
  });
}
function linhaDaRegra(r) {
  return `nome = ${r.name} · ${r.action === "allow" ? "permitir" : "bloquear"} · ` +
         `${r.direction === "in" ? "entrada" : "saída"} · ${r.protocol} portas ${r.local_ports || "*"} · ` +
         `perfis ${(r.profiles || []).join(",")}${r.program ? " · " + r.program : ""}`;
}
async function toggle(r) {
  const novo = !r.enabled;
  const corpo = el("div");
  corpo.appendChild(el("div", "", `<div class="linha-escrita">${esc(linhaDaRegra(r))}</div>`));
  corpo.appendChild(el("p", "", `<span style="font-size:12px;color:var(--muted)">Irá <b>${novo ? "HABILITAR" : "DESABILITAR"}</b> esta regra sua. Um prompt UAC vai aparecer; cancelando, nada muda.</span>`));
  modal(novo ? "Habilitar regra (UAC)" : "Desabilitar regra (UAC)", corpo, [
    ["Aplicar (UAC)", "primary", async () => {
      const res = await api("set_enabled", r.name, novo);
      if (res.ok) toast(`regra ${novo ? "habilitada" : "desabilitada"} ` + (res.verificada ? "· conferida por releitura" : "· ⚠ a releitura divergiu"), res.verificada ? "ok" : "warn");
      else toast(res.motivo || "falha", "err", 8000);
    }],
  ]);
}
async function remover(r) {
  const corpo = el("div");
  corpo.appendChild(el("div", "", `<div class="linha-escrita">${esc(linhaDaRegra(r))}</div>`));
  corpo.appendChild(el("p", "", `<span style="font-size:12px;color:var(--muted)">Remover abre o <b>UAC</b>. Cancelando, nada muda. Regras do sistema nunca aparecem aqui.</span>`));
  modal("Remover regra do Aegis (UAC)", corpo, [
    ["Remover (UAC)", "danger", async () => {
      const res = await api("remove_rule", r.name);
      toast(res.ok ? "regra removida " + (res.verificada ? "· conferido por releitura" : "· ⚠ releitura divergiu")
                   : res.motivo || "falha", res.ok ? "ok" : "err", 8000);
    }],
  ]);
}
$("btnAtivarLog").onclick = () => {
  const corpo = el("div");
  corpo.appendChild(el("p", "",
    "Vou pedir ao Windows (via <b>UAC</b>) para começar a gravar os bloqueios em " +
    "<code>%windir%\\System32\\LogFiles\\Firewall\\pfirewall.log</code> (bloqueios = sim, permitidas = não). " +
    "Isso muda <b>uma configuração de log do firewall</b> — nada mais."));
  modal("Ativar log de bloqueios (UAC)", corpo, [
    ["Ativar (UAC)", "amber", async () => {
      const res = await api("enable_firewall_log");
      toast(res.ok ? "log ativado — o feed vai povorar nos próximos ciclos"
                   : (res.motivo || "falha"), res.ok ? "ok" : "warn", 8000);
    }],
  ]);
};
$("btnNovaRegra").onclick = () => {
  const corpo = el("div");
  const f = {};
  const campo = (rotulo, placeholder = "") => {
    const i = el("input", "form"); i.placeholder = placeholder;
    corpo.appendChild(el("label", "", `<label class="campo">${rotulo}</label>`));
    corpo.appendChild(i); return i;
  };
  f.nome = campo("nome (prefixo \u201cAegis · \u201d obrigatório — é o selo de propriedade)", "Aegis · meu app escuta TCP 8080");
  const dupla = el("div", "dupla");
  f.dir = el("select", "form"); f.dir.innerHTML = '<option value="in">entrada</option><option value="out">saída</option>';
  f.proto = el("select", "form"); f.proto.innerHTML = '<option>tcp</option><option>udp</option><option value="any">qualquer</option>';
  f.acao = el("select", "form"); f.acao.innerHTML = '<option value="allow">permitir</option><option value="block">bloquear</option>';
  dupla.append(f.dir, f.proto); corpo.appendChild(dupla);
  f.portas = campo("portas (ex: 8080 ou 3476-3481; vazio = todas)", "6881");
  f.programa = campo("executável (caminho completo)", "C:\\path\\app.exe");
  const pf = campo("perfis (domain,private,public)", "private");
  corpo.appendChild(el("label", "", '<label class="campo">ação</label>')); corpo.appendChild(f.acao);
  modal("Nova regra → fila de revisão", corpo, [
    ["Levar para Revisão", "primary", async () => {
      let nome = f.nome.value.trim();
      if (nome && !nome.startsWith("Aegis ")) nome = "Aegis · " + nome;
      const spec = { name: nome, direction: f.dir.value, action: f.acao.value,
                     protocol: f.proto.value, local_ports: f.portas.value.trim(),
                     remote_ports: "", program: f.programa.value.trim(),
                     profiles: pf.value.split(",").map(x => x.trim()).filter(Boolean),
                     enabled: true, description: "" };
      const res = await api("new_rule", JSON.stringify(spec));
      if (res.ok) { toast("rascunho manual na fila — revise antes de aplicar"); irPara("revisao"); }
      else toast("validação recusou: " + res.motivo, "err", 9000);
    }],
  ]);
};

/* ---------- revisão ---------- */
async function renderRevisao() {
  let ds;
  try { ds = await api("drafts"); } catch (e) { toast("falha ao carregar fila: " + e, "err"); return; }
  const host = $("drafts"); host.replaceChildren();
  const pend = ds.filter(d => d.status === "pendente" || d.status === "aprovado");
  const fim = ds.filter(d => d.status === "rejeitado" || d.status === "aplicado");
  if (!ds.length) host.appendChild(el("div", "empty", "nenhum rascunho ainda — use \u201cEntender / liberar\u201d no Painel ou crie uma regra manual nas Regras"));
  pend.forEach(d => host.appendChild(cardDraft(d)));
  if (fim.length) {
    host.appendChild(el("h3", "", '<h3 style="font-size:13px;color:var(--muted);margin:18px 0 10px">histórico</h3>'));
    fim.slice(0, 30).forEach(d => host.appendChild(cardDraft(d, true)));
  }
}
function cardDraft(d, encerrado = false) {
  const c = el("div", "draft" + (encerrado ? " done" : ""));
  c.appendChild(el("div", "src", `<i></i> ${d.origin === "manual" ? "rascunho manual (você)" : "rascunho gerado por IA"} · ${esc(d.draft_id)} · ${esc(d.status)}`));
  c.appendChild(el("h3", "", esc(d.spec.name)));
  c.appendChild(el("p", "why", esc(d.rationale || "(sem justificativa)")));
  c.appendChild(el("div", "spec", esc(linhaDaRegra(d.spec)).replaceAll(" · ", "<br>")));
  const row = el("div", "row");
  row.appendChild(el("span", "confia",
    `confiança declarada: <b class="${esc(d.confidence)}">${esc(d.confidence || "?")}</b>${d.checked ? " · verificado: " + esc(d.checked) : ""}`));
  if (!encerrado) {
    const rejeitar = el("button", "btn ghost", "Rejeitar");
    rejeitar.onclick = async () => { const r = await api("reject", d.draft_id);
      if (!r.ok) toast(r.motivo, "err"); renderRevisao(); };
    const aplicar = el("button", "btn primary", "Aplicar regra (UAC)");
    aplicar.onclick = () => confirmarAplicar(d);
    row.append(rejeitar, aplicar);
  }
  c.appendChild(row);
  return c;
}
function confirmarAplicar(d, replace = false) {
  const corpo = el("div");
  corpo.appendChild(el("p", "", "A linha exata que será escrita no firewall, sob <b>UAC visível</b>:"));
  corpo.appendChild(el("div", "", `<div class="linha-escrita">${esc(linhaDaRegra(d.spec))}</div>`));
  const acoes = [["Cancelar", "ghost", async () => {}]];
  if (replace) acoes.push(["Substituir a existente (UAC)", "danger", async () => {
    const r = await api("approve", d.draft_id, true);
    resultadoAapply(d, r);
  }]);
  else acoes.push(["Aplicar (UAC)", "primary", async () => {
    const r = await api("approve", d.draft_id, false);
    resultadoAapply(d, r);
  }]);
  modal(replace ? "Conflito de regra — decidir" : "Aplicar regra (UAC)", corpo, acoes);
}
function resultadoAapply(d, r) {
  if (r.ok && r.verificada) { toast("aplicada + verificada por releitura"); renderRevisao(); return; }
  if (r.ok) { toast("aplicada, mas ⚠ a releitura não confirmou — veja a Auditoria", "warn", 9000); renderRevisao(); return; }
  if (r.motivo === "conflito") {
    const choques = (r.conflitos || []).map(c =>
      `${esc(c.name)}${c.built_in ? " (regra do sistema/terceiros — o Aegis NUNCA sobrescreve em silêncio)" : " (sua — pode substituir)"}`);
    const corpo = el("div");
    corpo.appendChild(el("p", "", "Já existe regra chocando:<br>" + choques.join("<br>")));
    const soProprias = (r.conflitos || []).every(c => !c.built_in);
    const acoes = [["Deixar pendente", "ghost", async () => {}]];
    if (soProprias) acoes.push(["Substituir (UAC)", "danger", async () => {
      const r2 = await api("approve", d.draft_id, true);
      resultadoAapply(d, r2);
    }]);
    modal("Conflito com regra existente", corpo, acoes);
    return;
  }
  toast(r.motivo || "falha ao aplicar", "err", 9000);
  renderRevisao();
}

/* ---------- transparência ---------- */
async function renderAudit() {
  let linhas;
  try { linhas = await api("audit", 200); } catch (e) { toast("falha na auditoria: " + e, "err"); return; }
  const tb = $("tbAudit"); tb.replaceChildren();
  if (!linhas.length) tb.appendChild(el("tr")).appendChild(el("td", "empty", "auditoria vazia — nada aconteceu ainda (é bom sinal, também)"));
  linhas.slice(-150).reverse().forEach(l => {
    const [quando, acao, alvo, resultado] = l.split(" | ");
    const tr = el("tr");
    tr.appendChild(el("td", "", esc(quando || l)));
    tr.appendChild(el("td", "proc", esc(acao || "")));
    tr.appendChild(el("td", "", esc(alvo || "")));
    const ok = /aplicada|removida|verificada|ativado|rejeitado|na fila|nada alterado|desabilitada|habilitada/.test(resultado || "");
    tr.appendChild(el("td", /falha|erro|divergiu|recusada|cancelado|indisponivel/.test(resultado || "") ? "res-warn" : (ok ? "res-ok" : ""), esc(resultado || "")));
    tb.appendChild(tr);
  });
}

/* ---------- laço ---------- */
async function renderTudo() { await renderPainel(); }
async function tick() {
  await renderPainel();
  const ativa = document.querySelector(".navitem.active");
  if (ativa) {
    if (ativa.dataset.p === "regras") renderRegras();
    if (ativa.dataset.p === "revisao") renderRevisao();
    if (ativa.dataset.p === "transp") renderAudit();
  }
}
async function esperarPonte(tenta = 0) {
  const api = aegisApi();
  if (api) { tick(); setInterval(tick, 2000); return; }
  if (tenta > 150) { toast("ponte com o motor não apareceu — a janela está aberta mas sem window.pywebview.api.aegis_api", "err", 30000); return; }
  setTimeout(() => esperarPonte(tenta + 1), 40);
}
esperarPonte();
