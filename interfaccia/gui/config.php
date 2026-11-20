<?php
// Configurazione della GUI. Nessun segreto qui dentro:
// RPC_URL, REGISTRY_ADDRESS e PRIVATE_KEY si passano come variabili d'ambiente
// al processo `php -S` e vengono ereditate dagli script Python.

// Cartella del progetto (dove stanno prove_image.py, model.py, build/ ...)
define('PROJECT_DIR', realpath(getenv('IXH_PROJECT_DIR') ?: __DIR__ . '/..'));

// Interprete Python (es. quello del virtualenv: /percorso/.venv/bin/python)
define('PYTHON', getenv('IXH_PYTHON') ?: 'python3');

define('BUILD_DIR', PROJECT_DIR . '/build');
define('UPLOAD_DIR', PROJECT_DIR . '/uploads');
define('MAX_UPLOAD_BYTES', 10 * 1024 * 1024);

// Prefisso delle cartelle create dalla GUI in build/
define('GUI_PREFIX', 'gui_');

// Explorer opzionale per i link alle transazioni, es. https://explorer.testnet.xrplevm.org/tx/
define('EXPLORER_TX_URL', getenv('IXH_EXPLORER_TX_URL') ?: '');
