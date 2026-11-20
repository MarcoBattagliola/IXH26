<?php
require __DIR__ . '/config.php';

set_time_limit(0);            // il proving può richiedere minuti
ignore_user_abort(true);

$action = $_GET['action'] ?? $_POST['action'] ?? '';

function json_out(array $data, int $code = 200): never {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function fail(string $msg, int $code = 400, string $detail = ''): never {
    json_out(['ok' => false, 'error' => $msg, 'detail' => $detail], $code);
}

/** Esegue uno script Python nella cartella del progetto, senza shell. Ritorna il JSON dell'ultima riga. */
function run_python(array $args): array {
    $cmd = array_merge([PYTHON, '-u'], $args);
    $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, PROJECT_DIR);
    if (!is_resource($proc)) fail('impossibile avviare Python (' . PYTHON . ')', 500);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    proc_close($proc);

    $lines = array_values(array_filter(array_map('trim', explode("\n", $stdout))));
    $res = $lines ? json_decode(end($lines), true) : null;
    if (!is_array($res)) {
        fail('risposta non valida dallo script Python', 500, substr($stderr . "\n" . $stdout, -3000));
    }
    if (empty($res['ok']) && empty($res['detail'])) $res['detail'] = substr($stderr, -3000);
    return $res;
}

function valid_id(?string $id): string {
    if (!$id || !preg_match('/^[A-Za-z0-9_\-]{1,80}$/', $id)) fail('id non valido');
    return $id;
}

function read_json(string $path): ?array {
    return is_file($path) ? json_decode(file_get_contents($path), true) : null;
}

function write_meta(string $id, array $meta): void {
    file_put_contents(BUILD_DIR . "/$id/gui_meta.json", json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}

switch ($action) {

case 'status':
    $files = [];
    foreach (['model.compiled', 'pk.key', 'vk.key', 'settings.json', 'threshold.json'] as $f) {
        $files[$f] = is_file(BUILD_DIR . "/$f");
    }
    $thr = read_json(BUILD_DIR . '/threshold.json');
    json_out([
        'ok' => true,
        'project_dir' => PROJECT_DIR,
        'files' => $files,
        'onnx' => is_file(PROJECT_DIR . '/detector.onnx'),
        'weights' => is_file(PROJECT_DIR . '/detector.pt'),
        'verifier_sol' => is_file(PROJECT_DIR . '/contracts/Verifier.sol'),
        'threshold' => $thr ? [
            'threshold_fixed' => $thr['threshold_fixed'],
            'output_scale' => $thr['output_scale'],
            'threshold' => $thr['threshold_fixed'] / (2 ** $thr['output_scale']),
        ] : null,
        // solo se sono impostate, mai i valori
        'env' => [
            'RPC_URL' => (bool)getenv('RPC_URL'),
            'REGISTRY_ADDRESS' => (bool)getenv('REGISTRY_ADDRESS'),
            'PRIVATE_KEY' => (bool)getenv('PRIVATE_KEY'),
        ],
        'registry_address' => getenv('REGISTRY_ADDRESS') ?: null,
        'explorer_tx_url' => EXPLORER_TX_URL,
        'has_report' => is_file(BUILD_DIR . '/testing_report.json'),
    ]);

case 'prove':
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') fail('usare POST', 405);
    $f = $_FILES['image'] ?? null;
    if (!$f || $f['error'] !== UPLOAD_ERR_OK) fail('caricamento fallito (codice ' . ($f['error'] ?? '?') . ')');
    if ($f['size'] > MAX_UPLOAD_BYTES) fail('immagine troppo grande (max 10 MB)');
    $info = @getimagesize($f['tmp_name']);
    $ext = ['image/jpeg' => 'jpg', 'image/png' => 'png', 'image/webp' => 'webp', 'image/bmp' => 'bmp'][$info['mime'] ?? ''] ?? null;
    if (!$ext) fail('formato non supportato (JPEG, PNG, WebP, BMP)');

    if (!is_dir(UPLOAD_DIR)) mkdir(UPLOAD_DIR, 0775, true);
    // Nome casuale: diventa anche il nome della cartella build/<id>/ usata da prove_image.py
    $id = GUI_PREFIX . date('Ymd_His') . '_' . bin2hex(random_bytes(3));
    $img = UPLOAD_DIR . "/$id.$ext";
    if (!move_uploaded_file($f['tmp_name'], $img)) fail('impossibile salvare il file', 500);

    $t0 = microtime(true);
    $res = run_python(['gui_prove.py', $img]);
    $res['elapsed_s'] = round(microtime(true) - $t0, 1);
    if (empty($res['ok'])) json_out($res, 500);

    $meta = [
        'id' => $id,
        'original_name' => basename($f['name']),
        'image_file' => basename($img),
        'created_at' => date('c'),
        'width' => $info[0], 'height' => $info[1],
        'result' => $res,
        'submission' => null,
    ];
    write_meta($id, $meta);
    json_out(['ok' => true, 'item' => $meta]);

case 'history':
    $items = [];
    foreach (glob(BUILD_DIR . '/' . GUI_PREFIX . '*/gui_meta.json') ?: [] as $p) {
        if ($m = read_json($p)) $items[] = $m;
    }
    usort($items, fn($a, $b) => strcmp($b['created_at'], $a['created_at']));
    json_out(['ok' => true, 'items' => $items]);

case 'submit':
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') fail('usare POST', 405);
    $id = valid_id($_POST['id'] ?? null);
    $meta = read_json(BUILD_DIR . "/$id/gui_meta.json");
    $calldata = BUILD_DIR . "/$id/calldata.json";
    if (!$meta || !is_file($calldata)) fail('prova non trovata', 404);
    $res = run_python(['gui_chain.py', 'submit', $calldata]);
    if (!empty($res['ok'])) {
        $meta['submission'] = $res + ['submitted_at' => date('c')];
        write_meta($id, $meta);
    }
    json_out($res, empty($res['ok']) ? 502 : 200);

case 'lookup':
    $h = $_GET['hash'] ?? '';
    if (!preg_match('/^0x[0-9a-fA-F]{1,64}$/', $h)) fail('hash non valido (atteso 0x...)');
    json_out(run_python(['gui_chain.py', 'lookup', $h]));

case 'chain_info':
    json_out(run_python(['gui_chain.py', 'info']));

case 'report':
    $r = read_json(BUILD_DIR . '/testing_report.json');
    if (!$r) fail('build/testing_report.json non trovato: eseguite python evaluate_zk.py', 404);
    // Per ogni campione indica se esiste una miniatura servibile (solo percorsi dentro il progetto)
    foreach ($r['samples'] as &$s) $s['name'] = basename($s['image']);
    json_out(['ok' => true, 'report' => $r]);

case 'image':
    $id = valid_id($_GET['id'] ?? null);
    $matches = glob(UPLOAD_DIR . "/$id.*");
    if (!$matches) { http_response_code(404); exit; }
    $mime = mime_content_type($matches[0]);
    if (!str_starts_with($mime, 'image/')) { http_response_code(403); exit; }
    header("Content-Type: $mime");
    header('Cache-Control: max-age=86400');
    readfile($matches[0]);
    exit;

case 'calldata':
    $id = valid_id($_GET['id'] ?? null);
    $p = BUILD_DIR . "/$id/calldata.json";
    if (!is_file($p)) { http_response_code(404); exit; }
    header('Content-Type: application/json');
    header("Content-Disposition: attachment; filename=\"calldata_$id.json\"");
    readfile($p);
    exit;

default:
    fail('azione sconosciuta', 404);
}
