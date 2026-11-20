"use strict";
const $ = (id) => document.getElementById(id);
let STATUS = null, CURRENT = null, FILE = null;

// ---------- utilità ----------
function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v; else if (k === "text") e.textContent = v; else e.setAttribute(k, v);
  }
  for (const k of kids) if (k != null) e.append(k);
  return e;
}
const short = (h) => h ? h.slice(0, 10) + "…" + h.slice(-6) : "";
const fmt = (x, d = 4) => (x == null ? "—" : Number(x).toFixed(d));
const badge = (isAi) => el("span", { class: "badge " + (isAi ? "ai" : "real"), text: isAi ? "AI" : "REALE" });

async function api(action, { method = "GET", body = null, params = {} } = {}) {
  const qs = new URLSearchParams({ action, ...params });
  const r = await fetch("api.php?" + qs, { method, body });
  let data;
  try { data = await r.json(); } catch { data = { ok: false, error: "risposta non JSON (HTTP " + r.status + ")" }; }
  return data;
}

function message(container, ok, title, detail) {
  container.replaceChildren(el("div", { class: "msg " + (ok ? "ok" : "err") },
    el("strong", { text: title }), detail ? el("pre", { text: detail }) : null));
}

let timer = null;
function overlay(show, text) {
  $("overlay").hidden = !show;
  clearInterval(timer);
  if (show) {
    $("overlay-text").textContent = text;
    const t0 = Date.now();
    $("overlay-timer").textContent = "0 s";
    timer = setInterval(() => $("overlay-timer").textContent = Math.round((Date.now() - t0) / 1000) + " s", 1000);
  }
}

// ---------- tab ----------
document.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x === b));
  document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.id === "tab-" + b.dataset.tab));
  if (b.dataset.tab === "history") loadHistory();
  if (b.dataset.tab === "report") loadReport();
}));

// ---------- stato ----------
async function loadStatus() {
  const s = await api("status");
  STATUS = s;
  const box = $("status");
  if (!s.ok) { box.replaceChildren(el("span", { class: "pill no", text: s.error })); return; }
  const circuitOk = Object.values(s.files).every(Boolean);
  const pills = [
    [circuitOk, circuitOk ? "Circuito pronto" : "Circuito incompleto: eseguite setup_circuit",
      Object.entries(s.files).map(([k, v]) => (v ? "✓ " : "✗ ") + k).join("\n")],
    [s.onnx, "detector.onnx"],
    [s.threshold != null, s.threshold ? `Soglia ${fmt(s.threshold.threshold, 3)} (scala 2^${s.threshold.output_scale})` : "threshold.json mancante"],
    [s.env.RPC_URL && s.env.REGISTRY_ADDRESS, s.env.RPC_URL && s.env.REGISTRY_ADDRESS ? "Registry configurato" : "RPC_URL / REGISTRY_ADDRESS non impostati"],
    [s.env.PRIVATE_KEY ? true : "warn", s.env.PRIVATE_KEY ? "Chiave di firma presente" : "PRIVATE_KEY assente: invio disabilitato"],
  ];
  box.replaceChildren(...pills.map(([ok, txt, title]) =>
    el("span", { class: "pill " + (ok === "warn" ? "warn" : ok ? "ok" : "no"), text: txt, title: title || "" })));
  updateProveButton();
}

// ---------- upload ----------
const drop = $("drop");
function setFile(f) {
  if (!f || !f.type.startsWith("image/")) return;
  FILE = f;
  $("preview").src = URL.createObjectURL(f);
  $("preview").hidden = false;
  $("drop-text").hidden = true;
  updateProveButton();
}
function updateProveButton() {
  const ready = STATUS && STATUS.ok && Object.values(STATUS.files).every(Boolean);
  $("btn-prove").disabled = !(FILE && ready);
}
$("file").addEventListener("change", (e) => setFile(e.target.files[0]));
["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
drop.addEventListener("drop", (e) => setFile(e.dataTransfer.files[0]));

$("btn-prove").addEventListener("click", async () => {
  const fd = new FormData();
  fd.append("image", FILE);
  overlay(true, "Generazione della prova ZK…");
  const r = await api("prove", { method: "POST", body: fd });
  overlay(false);
  if (!r.ok) {
    $("result-empty").hidden = false; $("result").hidden = true;
    message($("result-empty"), false, "Errore: " + r.error, r.detail);
    return;
  }
  showResult(r.item);
});

// ---------- risultato ----------
function showResult(item) {
  CURRENT = item;
  const r = item.result;
  $("result-empty").hidden = true;
  $("result").hidden = false;

  const v = $("verdict");
  v.className = "verdict " + (r.is_ai ? "ai" : "real");
  v.textContent = r.is_ai ? "Generata da AI" : "Immagine reale";

  const thr = r.threshold;
  const max = Math.max(1, thr * 2, r.zk_score);
  const pct = (x) => Math.max(0, Math.min(100, (x / max) * 100));
  $("meter-fill").style.width = pct(r.zk_score) + "%";
  $("meter-fill").style.background = r.is_ai ? "var(--ai)" : "var(--real)";
  $("meter-thr").style.left = pct(thr) + "%";
  $("meter-thr-label").textContent = "soglia " + fmt(thr, 3);
  $("meter-max").textContent = fmt(max, 2);

  $("r-score").textContent = fmt(r.zk_score);
  $("r-fixed").textContent = r.score_fixed + "  (soglia " + r.threshold_fixed + ")";
  $("r-hash").textContent = r.image_hash;
  $("r-ninst").textContent = r.n_instances;
  $("r-time").textContent = r.elapsed_s != null ? r.elapsed_s + " s" : "—";
  $("btn-calldata").href = "api.php?action=calldata&id=" + encodeURIComponent(item.id);

  const canSend = STATUS && STATUS.env.RPC_URL && STATUS.env.REGISTRY_ADDRESS && STATUS.env.PRIVATE_KEY;
  $("btn-submit").disabled = !canSend || !!item.submission;
  $("btn-submit").title = canSend ? "" : "Impostate RPC_URL, REGISTRY_ADDRESS e PRIVATE_KEY prima di avviare il server";
  $("submit-out").replaceChildren();
  if (item.submission) showSubmission(item.submission);
}

function txLink(hash) {
  const base = STATUS && STATUS.explorer_tx_url;
  return base ? el("a", { href: base + hash, target: "_blank", rel: "noopener", text: short(hash) }) : el("code", { text: hash });
}

function showSubmission(s) {
  const box = el("div", { class: "msg ok" },
    el("strong", { text: "Registrata on-chain " }), badge(s.is_ai),
    el("div", {}, "tx ", txLink(s.tx_hash)),
    el("div", { class: "muted", text: `blocco ${s.block} · gas ${s.gas_used} · chain ${s.chain_id}` }));
  $("submit-out").replaceChildren(box);
}

$("btn-submit").addEventListener("click", async () => {
  if (!CURRENT) return;
  if (!confirm("Inviare la prova al registry? La transazione costa gas.")) return;
  const fd = new FormData(); fd.append("id", CURRENT.id);
  overlay(true, "Simulazione e invio della transazione…");
  const r = await api("submit", { method: "POST", body: fd });
  overlay(false);
  if (!r.ok) {
    const hints = {
      AlreadyRegistered: "Questa immagine (stesso hash) è già nel registry.",
      InvalidProof: "Il Verifier ha rifiutato la prova: Verifier e chiavi corrispondono allo stesso setup?",
      WrongInstanceCount: "Numero di instances diverso da quello passato al costruttore del registry.",
      NegativeScore: "Lo score dimostrato è negativo.",
    };
    message($("submit-out"), false, (r.stage ? "Revert in " + r.stage + ": " : "Errore: ") + r.error, hints[r.error] || r.detail);
    return;
  }
  CURRENT.submission = r;
  $("btn-submit").disabled = true;
  showSubmission(r);
});

document.addEventListener("click", (e) => {
  const id = e.target.dataset && e.target.dataset.copy;
  if (id) navigator.clipboard.writeText($(id).textContent).then(() => { e.target.textContent = "copiato"; setTimeout(() => e.target.textContent = "copia", 1200); });
});

// ---------- storico ----------
async function loadHistory() {
  const body = $("history-body");
  const r = await api("history");
  if (!r.ok || !r.items.length) {
    body.replaceChildren(el("tr", {}, el("td", { colspan: 8, class: "empty", text: r.ok ? "Nessuna prova ancora." : r.error })));
    return;
  }
  body.replaceChildren(...r.items.map((it) => {
    const res = it.result;
    const open = el("button", { class: "btn small", text: "Apri" });
    open.addEventListener("click", () => { document.querySelector('[data-tab="prove"]').click(); showResult(it); });
    const look = el("button", { class: "link", text: short(res.image_hash), title: "Cerca nel registry" });
    look.addEventListener("click", () => { $("lookup-hash").value = res.image_hash; document.querySelector('[data-tab="lookup"]').click(); doLookup(); });
    return el("tr", {},
      el("td", {}, el("img", { src: "api.php?action=image&id=" + encodeURIComponent(it.id), alt: "" })),
      el("td", { text: it.original_name }),
      el("td", { text: new Date(it.created_at).toLocaleString("it-IT") }),
      el("td", { text: fmt(res.zk_score) }),
      el("td", {}, badge(res.is_ai)),
      el("td", {}, look),
      el("td", {}, it.submission ? txLink(it.submission.tx_hash) : el("span", { class: "muted", text: "—" })),
      el("td", {}, open));
  }));
}
$("btn-refresh").addEventListener("click", loadHistory);

// ---------- lookup ----------
async function doLookup() {
  const h = $("lookup-hash").value.trim();
  const out = $("lookup-out");
  out.replaceChildren(el("div", { class: "empty", text: "Interrogazione del registry…" }));
  const r = await api("lookup", { params: { hash: h } });
  if (!r.ok) return message(out, false, "Errore: " + r.error, r.detail);
  if (!r.exists) return message(out, false, "Nessun risultato registrato per questo hash.");
  out.replaceChildren(el("div", { class: "msg ok" },
    el("strong", { text: "Risultato verificato on-chain " }), badge(r.is_ai),
    el("dl", { class: "kv", style: "margin:12px 0 0" },
      el("dt", { text: "Score" }), el("dd", { text: fmt(r.score) + "  (" + r.score_fixed + ")" }),
      el("dt", { text: "Registrato il" }), el("dd", { text: new Date(r.timestamp * 1000).toLocaleString("it-IT") }),
      el("dt", { text: "Da" }), el("dd", {}, el("code", { class: "wrap", text: r.submitter })))));
}
$("lookup-form").addEventListener("submit", (e) => { e.preventDefault(); doLookup(); });

$("btn-chain").addEventListener("click", async () => {
  const out = $("chain-out");
  out.className = ""; out.replaceChildren(el("div", { class: "empty", text: "Lettura…" }));
  const r = await api("chain_info");
  if (!r.ok) return message(out, false, "Errore: " + r.error, r.detail);
  const loc = STATUS && STATUS.threshold;
  const same = (a, b) => loc ? (String(a) === String(b) ? " ✓" : " ✗ diverso dal locale (" + b + ")") : "";
  out.replaceChildren(el("dl", { class: "kv" },
    el("dt", { text: "Chain ID" }), el("dd", { text: r.chain_id }),
    el("dt", { text: "Registry" }), el("dd", {}, el("code", { class: "wrap", text: r.registry })),
    el("dt", { text: "Verifier" }), el("dd", {}, el("code", { class: "wrap", text: r.verifier })),
    el("dt", { text: "numInstances" }), el("dd", { text: r.num_instances }),
    el("dt", { text: "thresholdFixed" }), el("dd", { text: r.threshold_fixed + same(r.threshold_fixed, loc && loc.threshold_fixed) }),
    el("dt", { text: "outputScale" }), el("dd", { text: r.output_scale + same(r.output_scale, loc && loc.output_scale) })));
});

// ---------- report ----------
async function loadReport() {
  const out = $("report-out");
  const r = await api("report");
  if (!r.ok) { out.replaceChildren(el("div", { class: "empty", text: r.error })); return; }
  const rep = r.report, c = rep.confusion;
  const prec = c.tp / Math.max(1, c.tp + c.fp), rec = c.tp / Math.max(1, c.tp + c.fn);
  const stat = (v, l) => el("div", { class: "stat" }, el("div", { class: "v", text: v }), el("div", { class: "l", text: l }));
  const cell = (v, good) => el("td", { class: good ? "good" : "bad", text: v });

  out.replaceChildren(
    el("h2", { text: "Report di testing (evaluate_zk.py)" }),
    el("div", { class: "stats" },
      stat((rep.float_accuracy * 100).toFixed(2) + "%", "Accuracy float (test set)"),
      stat((prec * 100).toFixed(1) + "%", "Precisione classe AI"),
      stat((rec * 100).toFixed(1) + "%", "Recall classe AI"),
      stat(Math.round(rep.zk_float_agreement * rep.zk_sample_size) + "/" + rep.zk_sample_size, "Accordo float/ZK"),
      stat(rep.seed, "Seed del campione")),
    el("table", { class: "cm" },
      el("tr", {}, el("th"), el("th", { text: "pred AI" }), el("th", { text: "pred REALE" })),
      el("tr", {}, el("th", { text: "vero AI" }), cell(c.tp, true), cell(c.fn, false)),
      el("tr", {}, el("th", { text: "vero REALE" }), cell(c.fp, false), cell(c.tn, true))),
    el("table", { class: "tbl" },
      el("thead", {}, el("tr", {}, ...["Immagine", "Etichetta", "Score float", "Score ZK", "Verdetto ZK", "Float = ZK", "Hash"].map((t) => el("th", { text: t })))),
      el("tbody", {}, ...rep.samples.map((s) => el("tr", {},
        el("td", { text: s.name }),
        el("td", {}, badge(s.true_ai)),
        el("td", { text: fmt(s.float_score) }),
        el("td", { text: fmt(s.zk_score) }),
        el("td", {}, badge(s.zk_is_ai)),
        el("td", { text: s.decisions_agree ? "✓" : "✗ quantizzazione" }),
        el("td", {}, el("code", { text: short(s.image_hash) })))))));
}

loadStatus();
