/* Pedidos em atraso — página do comercial. Lê dados/atrasados.json (gerado
   pela Consulta de Pedidos do PCP) e mostra o mesmo relatório do PDF: o resumo
   por faixa de atraso e um cartão por pedido. Sem dependências. */
const CORES = { "1 a 5 dias": "#D97706", "6 a 10 dias": "#C2410C", "mais de 10 dias": "#991B1B" };
const SIGLA = { "Guarapuava": "GPVA", "Imbituva": "IMB", "Teixeira Soares": "TEX", "Ponta Grossa": "PG" };
const fmt = new Intl.NumberFormat("pt-BR");
const moeda = new Intl.NumberFormat("pt-BR", { style: "currency", currency: "BRL" });
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const semAcento = (s) => String(s || "").normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();
const data = (iso) => { if (!iso) return ""; const [a, m, d] = String(iso).slice(0, 10).split("-"); return `${d}/${m}/${a}`; };

let dados = null;
const filtro = { q: "", tipo: "", status: "", setor: "", segmento: "", faixa: "" };

function lerFiltro() {
  try {
    const u = new URLSearchParams(location.hash.slice(1));
    for (const k of Object.keys(filtro)) filtro[k] = u.get(k) || "";
  } catch { /* hash inválido: sem filtro */ }
}
function gravarFiltro() {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(filtro)) if (v) u.set(k, v);
  history.replaceState(null, "", u.toString() ? `#${u}` : location.pathname);
}

/* ---------- login: os dados vêm cifrados (AES-256-GCM); a chave de cada publicação vai
   embrulhada por usuário com a senha dele (PBKDF2-SHA256). Nada é enviado a servidor algum. */
const CHAVE_SESSAO = "kadesh-atrasos:sessao";
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const txt = (s) => new TextEncoder().encode(s);
function normUsuario(u) {
  const s = String(u || "").trim().split(/\s+/).join(" ").toLowerCase();
  return /^\d+$/.test(s) ? String(parseInt(s, 10)) : s;
}
async function hashUsuario(u) {
  const h = await crypto.subtle.digest("SHA-256", txt("kadesh-atrasos:" + normUsuario(u)));
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function lerCifrado() {
  const r = await fetch(`dados/atrasados.enc.json?v=${Date.now()}`, { cache: "no-store" });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}
async function entrar(usuario, senha) {
  const cif = await lerCifrado();
  const u = await hashUsuario(usuario);
  const achado = cif.usuarios.find((x) => (Array.isArray(x.u) ? x.u : [x.u]).includes(u));
  if (!achado) throw new Error("Usuário ou senha inválidos.");
  // a regra de senha da Consulta: sem caixa e sem espaço nas pontas
  const base = await crypto.subtle.importKey("raw", txt(String(senha || "").trim().toUpperCase()), "PBKDF2", false, ["deriveKey"]);
  const kek = await crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: b64(achado.sal), iterations: cif.iteracoes },
                                            base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  let chaveBruta;
  try { chaveBruta = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(achado.iv) }, kek, b64(achado.chave)); }
  catch { throw new Error("Usuário ou senha inválidos."); }
  const chave = await crypto.subtle.importKey("raw", chaveBruta, "AES-GCM", false, ["decrypt"]);
  const claro = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(cif.iv) }, chave, b64(cif.dados));
  // a sessão vale só enquanto a aba estiver aberta (sessionStorage)
  try { sessionStorage.setItem(CHAVE_SESSAO, JSON.stringify({ usuario, senha })); } catch { /* sem storage */ }
  return JSON.parse(new TextDecoder().decode(claro));
}
/* ---------- informações protegidas (13/11/2026): valor, pares pendentes, tipo de problema, classificação, setor, status e o
   motivo do atraso ficam EMBAÇADOS até alguém digitar a senha de liberação (um clique em qualquer uma abre o pedido de senha e,
   certa, tudo aparece). Número do pedido, cliente, dias de atraso, a 1ª, 2ª e 3ª data e o SEGMENTO (liberado a pedido do PCP, com o
   filtro de segmento) ficam sempre à vista.
   Enquanto protegidas, o que se vê embaçado NÃO é o dado: é um texto de enfeite com o mesmo formato (inspecionar a página, copiar
   ou procurar não mostra nada), e a busca e os filtros por essas informações ficam desligados. É uma trava de tela, não
   criptografia: quem entrou já tem os dados no navegador. A senha não está no código: só o verificador (PBKDF2-SHA256). */
const CHAVE_LIBERADO = "kadesh-atrasos:liberado";
const SENHA_LIBERA = { sal: "ce4XGu+kQ2rtBgk+rDMP4w==", iteracoes: 200000, hash: "Ryf2n7pU59Do69KldiHaBpGVmDmwOS1u5bPsKwfmaZE=" };
let liberado = false;
try { liberado = sessionStorage.getItem(CHAVE_LIBERADO) === "1"; } catch { /* sem storage */ }

async function senhaConfere(senha) {
  const base = await crypto.subtle.importKey("raw", txt(senha), "PBKDF2", false, ["deriveBits"]);
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: b64(SENHA_LIBERA.sal), iterations: SENHA_LIBERA.iteracoes }, base, 256));
  const alvo = b64(SENHA_LIBERA.hash);
  let dif = bits.length ^ alvo.length;
  for (let i = 0; i < alvo.length; i++) dif |= (bits[i] ?? 0) ^ alvo[i];
  return dif === 0;
}

/* o texto de enfeite NÃO deriva do dado (nem o tamanho, nem a forma): só do pedido e do campo, sorteado de forma estável para não
   "tremer" a cada atualização. Assim não vaza a classe do valor (status e setor são listas curtas) nem se o campo estava vazio. */
function sorteio(semente) {
  let h = 2166136261;
  for (const c of String(semente)) { h ^= c.charCodeAt(0); h = Math.imul(h, 16777619); }
  let a = h >>> 0;
  return () => {
    a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
/* `tipo`: "valor" (R$ 0.000,00), "num" (pares), "txt" (palavras curtas) ou "motivo" (frase longa) */
function enfeite(tipo, semente) {
  const rnd = sorteio(semente);
  const dig = (n) => Array.from({ length: n }, () => Math.floor(rnd() * 10)).join("");
  const LET = "abcdefghilmnoprstuv";
  const palavra = (n) => Array.from({ length: n }, () => LET[Math.floor(rnd() * LET.length)]).join("");
  if (tipo === "valor") return `R$ ${1 + Math.floor(rnd() * 98)}.${dig(3)},${dig(2)}`;
  if (tipo === "num") return dig(1 + Math.floor(rnd() * 3));
  const alvo = tipo === "motivo" ? 70 + Math.floor(rnd() * 100) : 10 + Math.floor(rnd() * 14);
  let s = "";
  while (s.length < alvo) s += (s ? " " : "") + palavra(3 + Math.floor(rnd() * 6));
  s = s.slice(0, alvo).trim();
  return s.charAt(0).toUpperCase() + s.slice(1);
}

let focoAntesLibera = null, errosLibera = 0, bloqueadoAteLibera = 0, abertoEmLibera = 0;
function avisoLibera(msg) { $("liberaErro").textContent = msg || ""; $("liberaErro").classList.toggle("hidden", !msg); }
function abrirLibera(origem) {
  if (liberado) return;
  focoAntesLibera = origem || document.activeElement;
  $("liberaSenha").value = "";
  $("liberaSenha").type = "password";                          // "mostrar senha" volta ao padrão a cada abertura
  $("liberaVerSenha").classList.remove("vendo");
  $("liberaVerSenha").setAttribute("aria-label", "Mostrar senha");
  avisoLibera("");
  abertoEmLibera = Date.now();
  $("libera").classList.remove("hidden");
  $("liberaSenha").focus();                                    // na hora, dentro do gesto do usuário (o teclado do celular só abre assim)
}
function fecharLibera() {
  $("libera").classList.add("hidden");
  const volta = focoAntesLibera && document.contains(focoAntesLibera) ? focoAntesLibera : $("btnOcultar");
  focoAntesLibera = null;
  if (volta && volta.focus && !volta.classList.contains("hidden")) volta.focus({ preventScroll: true });
}
function guardarLiberado() { try { if (liberado) sessionStorage.setItem(CHAVE_LIBERADO, "1"); else sessionStorage.removeItem(CHAVE_LIBERADO); } catch { /* sem storage */ } }
/* trava e destrava: o resto da tela (botão, aviso, busca e filtros) acompanha */
function aplicarProtecao() {
  guardarLiberado();
  $("btnOcultar").classList.toggle("hidden", !liberado);
  $("dicaProt").classList.toggle("hidden", liberado || !dados);
  $("fBusca").placeholder = liberado ? "Buscar pedido, cliente ou motivo…" : "Buscar pedido ou cliente…";
  if (dados) {
    const y = window.scrollY;                                  // travar/destravar refaz a lista inteira: a rolagem fica onde estava
    preencherFiltros(); gravarFiltro(); render();
    window.scrollTo(0, y);
  }
}

let usuariosLogin = [];          // [{numero, nome}] de quem tem acesso (vem no arquivo publicado)
let selLogin = null;
let indiceLista = -1;
const CHAVE_ULTIMO = "kadesh-atrasos:ultimo";

function aviso(msg) { $("loginErro").textContent = msg || ""; $("loginErro").classList.toggle("hidden", !msg); }
function escolher(u, focarSenha = true) {
  selLogin = u;
  $("loginUsuario").value = u ? u.nome : "";
  if (u) $("loginNumero").value = String(u.numero);
  fecharLista();
  aviso("");
  if (u && focarSenha) setTimeout(() => $("loginSenha").focus(), 0);
}
function fecharLista() { $("loginLista").classList.add("hidden"); $("loginUsuario").setAttribute("aria-expanded", "false"); indiceLista = -1; }
function abrirLista() {
  const termo = semAcento($("loginUsuario").value.trim());
  const lista = usuariosLogin
    .filter((u) => !termo || semAcento(u.nome).includes(termo) || String(u.numero).startsWith(termo))
    .sort((a, b) => a.nome.localeCompare(b.nome, "pt-BR")).slice(0, 60);
  $("loginLista").innerHTML = lista.length
    ? lista.map((u, i) => `<li role="option" id="loginOp${i}" data-numero="${u.numero}"><span>${esc(u.nome)}</span><b>${u.numero}</b></li>`).join("")
    : `<li class="vazio">Nenhum usuário com esse nome</li>`;
  $("loginLista").classList.remove("hidden");
  $("loginUsuario").setAttribute("aria-expanded", "true");
  indiceLista = -1;
}
function marcar(delta) {
  const itens = [...$("loginLista").querySelectorAll("li[data-numero]")];
  if (!itens.length) return;
  indiceLista = (indiceLista + delta + itens.length) % itens.length;
  itens.forEach((li, i) => li.classList.toggle("ativo", i === indiceLista));
  itens[indiceLista].scrollIntoView({ block: "nearest" });
}
const porNumero = (n) => usuariosLogin.find((u) => u.numero === Number(n)) || null;

async function mostrarLogin(msg) {
  liberado = false;                                             // quem volta ao login (sessão perdida, Sair) começa trancado de novo
  guardarLiberado();
  $("libera").classList.add("hidden");
  document.body.classList.add("bloqueado");
  $("login").classList.remove("hidden");
  aviso(msg);
  try { usuariosLogin = (await lerCifrado()).lista || []; } catch { usuariosLogin = []; }
  let lembrado = "";
  try { lembrado = localStorage.getItem(CHAVE_ULTIMO) || ""; } catch { /* sem storage */ }
  if (lembrado && !$("loginNumero").value) { $("loginNumero").value = lembrado; escolher(porNumero(lembrado), false); }
  setTimeout(() => (selLogin ? $("loginSenha") : $("loginNumero")).focus(), 30);
}

async function carregar() {
  let sess = null;
  try { sess = JSON.parse(sessionStorage.getItem(CHAVE_SESSAO) || "null"); } catch { /* sem storage */ }
  if (!sess) { mostrarLogin(); return; }
  try {
    dados = await entrar(sess.usuario, sess.senha);
  } catch (err) {
    try { sessionStorage.removeItem(CHAVE_SESSAO); } catch { /* sem storage */ }
    mostrarLogin(String(err.message).startsWith("HTTP") ? "Não foi possível carregar os dados agora." : "Entre de novo.");
    return;
  }
  document.body.classList.remove("bloqueado");
  $("login").classList.add("hidden");
  const gerado = new Date(dados.gerado_em);
  $("sub").textContent = `Atualizado em ${gerado.toLocaleDateString("pt-BR")} às ${gerado.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" })} · referência ${data(dados.hoje)}`;
  const horas = (Date.now() - gerado.getTime()) / 36e5;
  $("velho").classList.toggle("hidden", horas < 40);
  $("velho").textContent = horas >= 40 ? `Atenção: dados de ${Math.floor(horas)} h atrás — a atualização automática pode estar parada.` : "";
  $("regra").textContent = `Regra: ${dados.regra}.`;
  $("fSegmento").classList.toggle("hidden", !dados.campos.includes("segmento"));
  $("fSetor").classList.toggle("hidden", !dados.campos.includes("setor_gerador"));
  $("fStatus").classList.toggle("hidden", !dados.campos.includes("status"));
  $("btnOcultar").classList.toggle("hidden", !liberado);
  $("dicaProt").classList.toggle("hidden", liberado);
  $("fBusca").placeholder = liberado ? "Buscar pedido, cliente ou motivo…" : "Buscar pedido ou cliente…";
  preencherFiltros();
  render();
}

/* os filtros de status e setor mostram valores que estão protegidos: só se preenchem com a senha liberada (o de segmento é livre) */
function preencherFiltros() {
  const prot = (id, rot, campo) => {
    if (liberado) preencherSelect(id, rot, dados.pedidos.map((p) => p[campo]));
    else $(id).innerHTML = `<option value="">${rot}: protegido</option>`;
  };
  prot("fStatus", "Status", "status");
  prot("fSetor", "Setor", "setor_gerador");
  preencherSelect("fSegmento", "Segmento", dados.pedidos.map((p) => p.segmento));
  for (const [id, k] of [["fBusca", "q"], ["fTipo", "tipo"], ["fStatus", "status"], ["fSetor", "setor"], ["fSegmento", "segmento"]]) {
    $(id).value = filtro[k];
    const guardado = !liberado && (k === "status" || k === "setor");     // protegido: o filtro do endereço fica guardado (e ignorado) até liberar
    if ($(id).value !== filtro[k] && !guardado) filtro[k] = "";           // opção que sumiu dos dados: volta para "todos"
  }
}

function preencherSelect(id, rot, valores) {
  const vs = [...new Set(valores.filter(Boolean))].sort((a, b) => a.localeCompare(b, "pt-BR"));
  $(id).innerHTML = `<option value="">${rot}: todos</option>` + vs.map((v) => `<option>${esc(v)}</option>`).join("");
}

function filtrados() {
  const termos = semAcento(filtro.q).split(/\s+/).filter(Boolean);
  return dados.pedidos.filter((p) => {
    if (filtro.tipo && p.tipo !== filtro.tipo) return false;
    if (liberado && filtro.status && p.status !== filtro.status) return false;
    if (liberado && filtro.setor && p.setor_gerador !== filtro.setor) return false;
    if (filtro.segmento && p.segmento !== filtro.segmento) return false;
    if (filtro.faixa && p.faixa !== filtro.faixa) return false;
    if (termos.length) {
      // protegido, a busca só olha o que está à vista (pedido e cliente): procurar não pode revelar o que está embaçado
      const txt = semAcento((liberado ? [p.pedido, p.cliente, p.observacoes_pcp, p.defeito, p.tipo_problema, p.materia_prima]
                                      : [p.pedido, p.cliente]).join(" "));
      if (!termos.every((t) => txt.includes(t))) return false;
    }
    return true;
  });
}

function render() {
  const lista = filtrados();
  const comValor = dados.campos.includes("valor");
  // resumo: as três faixas e o total, recalculados sobre a lista filtrada (sem o filtro de faixa)
  const semFaixa = (() => { const f = filtro.faixa; filtro.faixa = ""; const l = filtrados(); filtro.faixa = f; return l; })();
  const tot = semFaixa.length || 1;
  // protegido, pares e valor só aparecem para a carteira inteira: com busca, tipo ou segmento o recorte pode ser UM pedido, e o total dele
  // seria o valor e os pares que estão embaçados no cartão
  const detalhe = liberado || !(filtro.q || filtro.tipo || filtro.segmento);
  const caixa = (rot, cor, ps, chave) => {
    const pares = ps.reduce((s, p) => s + (p.pendente || 0), 0);
    const valor = ps.reduce((s, p) => s + (p.valor || 0), 0);
    const am = ps.filter((p) => p.tipo === "AMOSTRA").length;
    return `<button type="button" class="caixa${filtro.faixa === chave && chave ? " ativa" : ""}" data-faixa="${esc(chave)}" style="--cor:${cor}">` +
      `<small>${esc(rot)}</small><b>${fmt.format(ps.length)}</b>` +
      `<span>${ps.length === 1 ? "pedido" : "pedidos"}${am ? ` (${am} amostra${am > 1 ? "s" : ""})` : ""}${detalhe ? ` · ${fmt.format(pares)} pares${comValor ? ` · ${moeda.format(valor)}` : ""}` : " · pares e valor protegidos"}</span>` +
      `<div class="barra"><i style="width:${Math.round((ps.length / tot) * 100)}%"></i></div></button>`;
  };
  $("resumo").innerHTML = Object.entries(CORES).map(([f, cor]) => caixa(f, cor, semFaixa.filter((p) => p.faixa === f), f)).join("") +
    caixa("Total em atraso", "#C10015", semFaixa, "");
  $("contagem").innerHTML = `<b>${fmt.format(lista.length)}</b> ${lista.length === 1 ? "pedido" : "pedidos"} na lista`;
  $("vazio").classList.toggle("hidden", lista.length > 0);
  $("lista").innerHTML = lista.map(cartao).join("");
}

function cartao(p) {
  const cor = CORES[p.faixa] || "#C10015";
  const dica = "Informação protegida: clique e digite a senha para ver";
  let primeiraParada = true;                                   // só a 1ª informação protegida de cada cartão entra na ordem do Tab (8 por cartão eram demais)
  const parada = () => { const t = primeiraParada ? 0 : -1; primeiraParada = false; return t; };
  // `prot`: campo protegido (embaçado, com texto de enfeite, até a senha ser digitada); vale o tipo do enfeite: "valor", "num" ou "txt"
  const campo = (rot, v, destaque, prot) => prot && !liberado
    ? `<div class="campo prot"><small>${rot}</small><b class="oculto" role="button" tabindex="${parada()}" title="${dica}" aria-label="${rot}: protegido, ative para digitar a senha">${esc(enfeite(prot, p.pedido + "|" + rot))}</b></div>`
    : `<div class="campo${destaque ? " destaque" : ""}"><small>${rot}</small>` + (v ? `<b>${esc(v)}</b>` : `<b class="vazio">—</b>`) + `</div>`;
  const tem = (c) => dados.campos.includes(c);
  const setor = p.setor_gerador ? p.setor_gerador + (p.unidade_setor ? ` · ${SIGLA[p.unidade_setor] || p.unidade_setor}` : "") : "";
  const campos = [
    tem("segmento") ? campo("Segmento", p.segmento) : "",
    campo("1ª data", data(p.previsao_1)), campo("2ª data", data(p.previsao_2)), campo("3ª data", data(p.previsao_3), true),
    tem("valor") ? campo("Valor", p.valor ? moeda.format(p.valor) : "", false, "valor") : "",
    tem("pendente") ? campo("Pares pendentes", p.pendente ? fmt.format(p.pendente) : "", false, "num") : "",
    tem("defeito") ? campo("Tipo de problema", p.defeito, false, "txt") : "",
    tem("tipo_problema") ? campo("Classificação", p.tipo_problema, false, "txt") : "",
    tem("setor_gerador") ? campo("Setor gerador", setor, false, "txt") : "",
    tem("status") ? campo("Status", p.status, false, "txt") : "",
  ].join("");
  const motivo = (tem("observacoes_pcp") || tem("materia_prima")) && !liberado
    ? `<div class="dir prot"><small>Motivo de atraso</small><p class="oculto" role="button" tabindex="${parada()}" title="${dica}" aria-label="Motivo de atraso: protegido, ative para digitar a senha">${esc(enfeite("motivo", p.pedido + "|motivo"))}</p></div>`
    : tem("observacoes_pcp") || tem("materia_prima")
    ? `<div class="dir"><small>Motivo de atraso</small>` +
      (p.materia_prima ? `<p class="mp">Matéria-prima: ${esc(p.materia_prima)}</p>` : "") +
      (p.observacoes_pcp ? `<p>${esc(p.observacoes_pcp)}</p>` : (p.materia_prima ? "" : `<p class="sem">Motivo de atraso não informado</p>`)) + `</div>`
    : `<div class="dir"></div>`;
  return `<article class="card" style="--cor:${cor}"><div class="tira"></div><div class="esq">` +
    `<div class="topo-card"><span class="ped">PEDIDO ${esc(p.pedido)}</span>` +
      (p.tipo === "AMOSTRA" ? `<span class="tag">AMOSTRA</span>` : "") +
      `<span class="cli" title="${esc(p.cliente)}">${esc(p.cliente || "")}</span>` +
      `<span class="dias">${fmt.format(p.dias)} ${p.dias === 1 ? "DIA" : "DIAS"} DE ATRASO</span></div>` +
    `<div class="campos">${campos}</div></div>${motivo}</article>`;
}

function ligar() {
  const muda = () => { gravarFiltro(); render(); };
  $("fBusca").addEventListener("input", (e) => { filtro.q = e.target.value.trim(); muda(); });
  $("fTipo").addEventListener("change", (e) => { filtro.tipo = e.target.value; muda(); });
  $("fStatus").addEventListener("change", (e) => { filtro.status = e.target.value; muda(); });
  $("fSetor").addEventListener("change", (e) => { filtro.setor = e.target.value; muda(); });
  $("fSegmento").addEventListener("change", (e) => { filtro.segmento = e.target.value; muda(); });
  $("fLimpar").addEventListener("click", () => {
    Object.keys(filtro).forEach((k) => { filtro[k] = ""; });
    for (const id of ["fBusca", "fTipo", "fStatus", "fSetor", "fSegmento"]) $(id).value = "";
    muda();
  });
  $("resumo").addEventListener("click", (e) => {
    const b = e.target.closest(".caixa");
    if (!b) return;
    filtro.faixa = filtro.faixa === b.dataset.faixa ? "" : b.dataset.faixa;
    muda();
  });
  $("btnImprimir").addEventListener("click", () => window.print());
  /* informações protegidas: clicar (ou Enter/Espaço) numa informação embaçada, ou nos filtros de status e setor, pede a senha */
  $("lista").addEventListener("click", (e) => { const p = e.target.closest(".prot"); if (p && !liberado) abrirLibera(p.querySelector(".oculto")); });
  $("lista").addEventListener("keydown", (e) => {
    if ((e.key === "Enter" || e.key === " ") && e.target.classList && e.target.classList.contains("oculto")) { e.preventDefault(); abrirLibera(e.target); }
  });
  for (const id of ["fStatus", "fSetor"]) {
    const s = $(id);
    s.addEventListener("mousedown", (e) => { if (!liberado) { e.preventDefault(); abrirLibera(s); } });
    s.addEventListener("keydown", (e) => { if (!liberado && ["Enter", " ", "ArrowDown", "ArrowUp"].includes(e.key)) { e.preventDefault(); abrirLibera(s); } });
  }
  $("btnOcultar").addEventListener("click", () => { liberado = false; aplicarProtecao(); $("fBusca").focus({ preventScroll: true }); });
  $("liberaCancelar").addEventListener("click", fecharLibera);
  // o fundo escuro fecha com um clique de verdade nele; o 2º clique de um duplo clique no campo cai no fundo e é ignorado (400 ms)
  $("libera").addEventListener("click", (e) => { if (e.target === $("libera") && Date.now() - abertoEmLibera > 400) fecharLibera(); });
  document.addEventListener("keydown", (e) => {                 // no documento: Esc e Tab valem mesmo se o foco sair do pedido de senha
    if ($("libera").classList.contains("hidden")) return;
    if (e.key === "Escape") { e.preventDefault(); fecharLibera(); return; }
    if (e.key !== "Tab") return;
    const f = [...$("libera").querySelectorAll("input, button")].filter((x) => !x.disabled && x.offsetParent !== null);
    if (!f.length) return;
    const i = f.indexOf(document.activeElement);
    if (i === -1) { e.preventDefault(); f[e.shiftKey ? f.length - 1 : 0].focus(); }
    else if (e.shiftKey && i === 0) { e.preventDefault(); f[f.length - 1].focus(); }
    else if (!e.shiftKey && i === f.length - 1) { e.preventDefault(); f[0].focus(); }
  });
  $("liberaVerSenha").addEventListener("click", () => {
    const s = $("liberaSenha");
    const ver = s.type === "password";
    s.type = ver ? "text" : "password";
    $("liberaVerSenha").classList.toggle("vendo", ver);
    $("liberaVerSenha").setAttribute("aria-label", ver ? "Ocultar senha" : "Mostrar senha");
  });
  $("liberaSenha").addEventListener("input", () => avisoLibera(""));
  $("liberaForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const espera = Math.ceil((bloqueadoAteLibera - Date.now()) / 1000);
    if (espera > 0) { avisoLibera(`Muitas tentativas. Aguarde ${espera} s e tente de novo.`); return; }
    const senha = $("liberaSenha").value.trim();
    if (!senha) { avisoLibera("Informe a senha."); $("liberaSenha").focus(); return; }
    const b = $("liberaOk");
    b.disabled = true;
    b.textContent = "Conferindo…";
    try {
      const ok = await senhaConfere(senha);
      if (!ok) {
        errosLibera += 1;
        if (errosLibera >= 5) { errosLibera = 0; bloqueadoAteLibera = Date.now() + 30000; avisoLibera("Muitas tentativas. Aguarde 30 segundos e tente de novo."); }
        else avisoLibera("Senha incorreta.");
        $("liberaSenha").value = "";
        $("liberaSenha").focus();
        return;
      }
      errosLibera = 0;
      liberado = true;
      $("liberaSenha").value = "";
      avisoLibera("");
      aplicarProtecao();
      fecharLibera();
    } catch {
      avisoLibera("Não foi possível conferir a senha neste navegador.");
    } finally {
      b.disabled = false;
      b.textContent = "Liberar";
    }
  });
  $("btnSair").addEventListener("click", () => {
    try { sessionStorage.removeItem(CHAVE_SESSAO); } catch { /* sem storage */ }
    liberado = false;                                             // sair tranca de novo as informações
    guardarLiberado();
    $("libera").classList.add("hidden");
    dados = null;
    $("lista").innerHTML = "";
    $("loginSenha").value = "";
    fecharLista();
    mostrarLogin();
  });
  $("loginNumero").addEventListener("input", (e) => {
    const dig = e.target.value.replace(/\D/g, "").slice(0, 5);
    e.target.value = dig;
    selLogin = dig ? porNumero(dig) : null;
    $("loginUsuario").value = selLogin ? selLogin.nome : "";
    aviso("");
  });
  $("loginNumero").addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); if (selLogin) $("loginSenha").focus(); }
  });
  const usuario = $("loginUsuario");
  usuario.addEventListener("input", () => { selLogin = null; $("loginNumero").value = ""; abrirLista(); });
  usuario.addEventListener("focus", () => usuario.select());
  usuario.addEventListener("click", abrirLista);
  usuario.addEventListener("blur", () => setTimeout(fecharLista, 120));
  usuario.addEventListener("keydown", (e) => {
    const aberta = !$("loginLista").classList.contains("hidden");
    if (e.key === "ArrowDown") { e.preventDefault(); if (!aberta) abrirLista(); marcar(1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); if (aberta) marcar(-1); }
    else if (e.key === "Escape") fecharLista();
    else if (e.key === "Enter" && aberta) {
      e.preventDefault();
      const itens = [...$("loginLista").querySelectorAll("li[data-numero]")];
      const li = itens[indiceLista] || (itens.length === 1 ? itens[0] : null);
      if (li) escolher(porNumero(li.dataset.numero));
    }
  });
  $("loginLista").addEventListener("mousedown", (e) => {
    const li = e.target.closest("li[data-numero]");
    if (!li) return;
    e.preventDefault();
    escolher(porNumero(li.dataset.numero));
  });
  $("loginVerSenha").addEventListener("click", () => {
    const s = $("loginSenha");
    const ver = s.type === "password";
    s.type = ver ? "text" : "password";
    $("loginVerSenha").classList.toggle("vendo", ver);
    $("loginVerSenha").setAttribute("aria-label", ver ? "Ocultar senha" : "Mostrar senha");
  });
  $("loginSenha").addEventListener("input", () => aviso(""));
  $("loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    // o número escolhido; sem ele, o texto do usuário (logins avulsos do PCP, ex.: comercial)
    const login = selLogin ? String(selLogin.numero) : $("loginUsuario").value.trim();
    if (!login) { aviso($("loginNumero").value ? `Não existe usuário com o número ${$("loginNumero").value}.` : "Informe o número ou escolha o usuário."); $("loginNumero").focus(); return; }
    if (!$("loginSenha").value) { aviso("Informe a senha."); $("loginSenha").focus(); return; }
    const b = $("loginEntrar");
    b.disabled = true;
    b.textContent = "Entrando…";
    aviso("");
    try {
      dados = await entrar(login, $("loginSenha").value);
      $("loginSenha").value = "";
      if (selLogin) { try { localStorage.setItem(CHAVE_ULTIMO, String(selLogin.numero)); } catch { /* sem storage */ } }
      await carregar();
    } catch (err) {
      aviso(String(err.message).startsWith("HTTP") ? "Não foi possível carregar os dados agora." : err.message);
      $("loginSenha").value = "";
      setTimeout(() => $("loginSenha").focus(), 0);
    } finally {
      b.disabled = false;
      b.textContent = "Acessar";
    }
  });
}

lerFiltro();
ligar();
carregar();
setInterval(() => { if (dados) carregar(); }, 10 * 60 * 1000);   // a página aberta se atualiza sozinha
