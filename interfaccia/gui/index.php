<?php require __DIR__ . '/config.php'; ?>
<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IXH26 · Rilevatore reale vs AI verificabile</title>
<link rel="stylesheet" href="assets/style.css">
</head>
<body>
<header class="top">
  <div class="brand">
    <span class="logo">◆</span>
    <div>
      <h1>IXH26 — Reale vs AI</h1>
      <p>Classificazione con prova zero-knowledge (EZKL · Halo2) e registro on-chain</p>
    </div>
  </div>
  <nav class="tabs" role="tablist">
    <button class="tab active" data-tab="prove">Analizza</button>
    <button class="tab" data-tab="history">Storico</button>
    <button class="tab" data-tab="lookup">Verifica on-chain</button>
    <button class="tab" data-tab="report">Report di testing</button>
  </nav>
</header>

<main>
  <!-- Stato del setup -->
  <section class="status" id="status">
    <span class="pill muted">Controllo setup…</span>
  </section>

  <!-- ANALIZZA -->
  <section class="panel active" id="tab-prove">
    <div class="grid2">
      <div class="card">
        <h2>1 · Carica un'immagine</h2>
        <label class="drop" id="drop">
          <input type="file" id="file" accept="image/jpeg,image/png,image/webp,image/bmp" hidden>
          <img id="preview" alt="" hidden>
          <span id="drop-text">Trascina qui un'immagine o <u>sceglila</u><br><small>JPEG, PNG, WebP, BMP · max 10 MB · ridotta a 32×32 nel circuito</small></span>
        </label>
        <button class="btn primary" id="btn-prove" disabled>Genera prova ZK</button>
        <p class="hint">Esegue <code>gen-witness → prove → verify → encode-evm-calldata</code>. Può richiedere qualche minuto.</p>
      </div>

      <div class="card" id="result-card">
        <h2>2 · Risultato</h2>
        <div id="result-empty" class="empty">Nessuna prova ancora generata.</div>
        <div id="result" hidden>
          <div class="verdict" id="verdict"></div>
          <div class="meter"><div class="fill" id="meter-fill"></div><div class="thr" id="meter-thr"></div></div>
          <div class="meter-legend"><span>0</span><span id="meter-thr-label"></span><span id="meter-max"></span></div>
          <dl class="kv">
            <dt>Score ZK</dt><dd id="r-score"></dd>
            <dt>Score (virgola fissa)</dt><dd><code id="r-fixed"></code></dd>
            <dt>Hash Poseidon immagine</dt><dd><code class="wrap" id="r-hash"></code> <button class="link" data-copy="r-hash">copia</button></dd>
            <dt>Public instances</dt><dd id="r-ninst"></dd>
            <dt>Tempo di proving</dt><dd id="r-time"></dd>
          </dl>
          <div class="actions">
            <a class="btn" id="btn-calldata" download>Scarica calldata.json</a>
            <button class="btn primary" id="btn-submit">3 · Registra on-chain</button>
          </div>
          <div id="submit-out"></div>
        </div>
      </div>
    </div>
    <p class="disclaimer">La prova garantisce che <em>il modello certificato dal Verifier</em> ha prodotto quel punteggio su quell'immagine. Non dimostra che l'immagine sia autentica.</p>
  </section>

  <!-- STORICO -->
  <section class="panel" id="tab-history">
    <div class="card">
      <div class="row-between"><h2>Prove generate dalla GUI</h2><button class="btn small" id="btn-refresh">Aggiorna</button></div>
      <table class="tbl">
        <thead><tr><th></th><th>Immagine</th><th>Data</th><th>Score</th><th>Verdetto</th><th>Hash</th><th>On-chain</th><th></th></tr></thead>
        <tbody id="history-body"><tr><td colspan="8" class="empty">Caricamento…</td></tr></tbody>
      </table>
    </div>
  </section>

  <!-- LOOKUP -->
  <section class="panel" id="tab-lookup">
    <div class="grid2">
      <div class="card">
        <h2>Cerca un'immagine nel registry</h2>
        <form id="lookup-form" class="inline">
          <input type="text" id="lookup-hash" placeholder="0x… hash Poseidon" spellcheck="false" required>
          <button class="btn primary">Cerca</button>
        </form>
        <div id="lookup-out"></div>
      </div>
      <div class="card">
        <div class="row-between"><h2>Parametri del contratto</h2><button class="btn small" id="btn-chain">Leggi dalla chain</button></div>
        <div id="chain-out" class="empty">Premi “Leggi dalla chain” per confrontare soglia e scala con quelle locali.</div>
      </div>
    </div>
  </section>

  <!-- REPORT -->
  <section class="panel" id="tab-report">
    <div id="report-out" class="card"><div class="empty">Caricamento…</div></div>
  </section>
</main>

<div class="overlay" id="overlay" hidden>
  <div class="spinner"></div>
  <p id="overlay-text">Generazione della prova…</p>
  <p class="muted" id="overlay-timer">0 s</p>
</div>

<script src="assets/app.js"></script>
</body>
</html>
