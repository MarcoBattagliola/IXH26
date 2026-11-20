# Interfaccia grafica (PHP)

## Installazione
Copiate nella **radice del progetto** (accanto a `prove_image.py`):

```
gui/             <- l'interfaccia PHP
gui_prove.py     <- wrapper: prove() -> JSON
gui_chain.py     <- wrapper: submit / lookup / info sul registry -> JSON
```

Requisiti: PHP ≥ 8.1, lo stesso ambiente Python del progetto (ezkl, torch, eth_abi, web3).

## Avvio
Dalla radice del progetto, dopo aver eseguito `setup_circuit` e il deploy:

```bash
export IXH_PYTHON="$PWD/.venv/bin/python"     # se usate un virtualenv
export RPC_URL=...  REGISTRY_ADDRESS=0x...
export PRIVATE_KEY=...                         # solo in locale, mai nel repo
# opzionale: export IXH_EXPLORER_TX_URL="https://<explorer>/tx/"
php -S 127.0.0.1:8080 -t gui
```

Aprite http://127.0.0.1:8080

Senza `PRIVATE_KEY` la GUI funziona lo stesso: proving, storico, lookup e report;
manca solo l'invio. Ascoltate solo su 127.0.0.1: chi raggiunge il server può far firmare
transazioni con la vostra chiave.

## Schede
- **Analizza**: upload → `gen-witness/prove/verify/encode-evm-calldata` → verdetto, score vs soglia,
  hash Poseidon, download `calldata.json`, pulsante "Registra on-chain" (prima simula, poi invia).
- **Storico**: tutte le prove fatte dalla GUI (`build/gui_*/gui_meta.json`), con eventuale tx.
- **Verifica on-chain**: `results(imageHash)` del registry, più il confronto tra
  `thresholdFixed`/`outputScale` on-chain e `build/threshold.json`.
- **Report di testing**: legge `build/testing_report.json` di `evaluate_zk.py`
  (accuracy, matrice di confusione, precisione/recall, accordo float/ZK).

Le immagini caricate finiscono in `uploads/`: aggiungete `uploads/` e `build/gui_*` al `.gitignore`.
