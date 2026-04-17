<?php
/**
 * save.php - бэкенд для сбора ответов анкеты.
 *
 * Эндпоинты:
 *   POST /save.php?action=response         - сохранить заполненную анкету
 *   POST /save.php?action=contact          - сохранить email для отчёта
 *   POST /save.php?action=login            - проверить ключ администратора
 *   GET  /save.php?action=export           - скачать ответы (требует X-Admin-Key)
 *   GET  /save.php?action=export_contacts  - скачать контакты (требует X-Admin-Key)
 *   GET  /save.php?action=stats            - статистика (требует X-Admin-Key)
 *
 * Ключ администратора и прочие настройки берутся из config.php (рядом).
 */

declare(strict_types=1);

// === CONFIG ===
$configPath = __DIR__ . '/config.php';
if (!is_file($configPath)) {
    http_response_code(500);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'error' => 'config_missing',
        'message' => 'Файл config.php не найден. Скопируйте config.example.php в config.php и впишите admin_key.',
    ], JSON_UNESCAPED_UNICODE);
    exit;
}
$cfg = require $configPath;
if (!is_array($cfg) || empty($cfg['admin_key']) || $cfg['admin_key'] === 'CHANGE_ME') {
    http_response_code(500);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'error' => 'config_invalid',
        'message' => 'В config.php не задан admin_key.',
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

define('ADMIN_KEY',     (string)$cfg['admin_key']);
define('ALLOWED_ORIGIN', isset($cfg['allowed_origin']) ? (string)$cfg['allowed_origin'] : '');
define('MAX_BODY_BYTES', isset($cfg['max_body_bytes']) ? (int)$cfg['max_body_bytes'] : 200000);
define('MIN_FILL_MS',    isset($cfg['min_fill_ms'])    ? (int)$cfg['min_fill_ms']    : 30000);
define('RATE_LIMIT_PER_MIN', isset($cfg['rate_limit_per_min']) ? (int)$cfg['rate_limit_per_min'] : 10);
define('DATA_DIR', __DIR__ . '/data');

// === CORS ===
// По умолчанию фронт и бэк на одном домене, CORS не нужен. Если в конфиге задан
// allowed_origin - разрешаем только его (для случая, когда анкета встраивается
// на другой сайт).
if (ALLOWED_ORIGIN !== '' && isset($_SERVER['HTTP_ORIGIN']) && $_SERVER['HTTP_ORIGIN'] === ALLOWED_ORIGIN) {
    header('Access-Control-Allow-Origin: ' . ALLOWED_ORIGIN);
    header('Vary: Origin');
    header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, X-Admin-Key');
}
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// === Директория data/ ===
if (!is_dir(DATA_DIR)) {
    @mkdir(DATA_DIR, 0755, true);
}
$dataHtaccess = DATA_DIR . '/.htaccess';
if (!is_file($dataHtaccess)) {
    @file_put_contents(
        $dataHtaccess,
        "# Apache 2.4\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n" .
        "# Apache 2.2\n<IfModule !mod_authz_core.c>\n    Order allow,deny\n    Deny from all\n</IfModule>\n"
    );
}

// === Вспомогательные функции ===
function respond(int $status, array $payload): void {
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_UNICODE);
    exit;
}

function readJsonBody(int $maxBytes): array {
    $raw = file_get_contents('php://input');
    if ($raw === false) respond(400, ['error' => 'read_failed']);
    if (strlen($raw) > $maxBytes) respond(413, ['error' => 'payload_too_large']);
    if ($raw === '') respond(400, ['error' => 'empty_body']);
    try {
        $data = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
    } catch (\JsonException $e) {
        respond(400, ['error' => 'invalid_json']);
    }
    if (!is_array($data)) respond(400, ['error' => 'invalid_json']);
    return $data;
}

function clientIp(): string {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $parts = explode(',', (string)$_SERVER['HTTP_X_FORWARDED_FOR']);
        $candidate = trim($parts[0]);
        if (filter_var($candidate, FILTER_VALIDATE_IP)) $ip = $candidate;
    }
    return $ip;
}

/** Rate limit на окно 60 секунд по IP. */
function checkRateLimit(string $ip, int $max): void {
    $file = DATA_DIR . '/ratelimit.json';
    $now = time();
    $window = 60;
    $store = [];

    $fp = @fopen($file, 'c+');
    if ($fp === false) return;
    try {
        flock($fp, LOCK_EX);
        $size = filesize($file);
        $content = $size > 0 ? fread($fp, $size) : '';
        if ($content !== '' && $content !== false) {
            $decoded = json_decode($content, true);
            if (is_array($decoded)) $store = $decoded;
        }

        foreach ($store as $k => $entry) {
            if (!is_array($entry) || ($entry['t'] ?? 0) < $now - $window) {
                unset($store[$k]);
            }
        }

        $entry = $store[$ip] ?? ['t' => $now, 'n' => 0];
        if ($entry['t'] < $now - $window) {
            $entry = ['t' => $now, 'n' => 0];
        }
        $entry['n'] += 1;
        $store[$ip] = $entry;

        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, json_encode($store, JSON_UNESCAPED_UNICODE));
        fflush($fp);

        if ($entry['n'] > $max) {
            flock($fp, LOCK_UN);
            fclose($fp);
            respond(429, ['error' => 'rate_limited']);
        }
    } finally {
        if (is_resource($fp)) {
            @flock($fp, LOCK_UN);
            @fclose($fp);
        }
    }
}

function requireAdmin(): void {
    $key = '';
    if (!empty($_SERVER['HTTP_X_ADMIN_KEY'])) {
        $key = (string)$_SERVER['HTTP_X_ADMIN_KEY'];
    } elseif (function_exists('apache_request_headers')) {
        $h = apache_request_headers();
        if (!empty($h['X-Admin-Key'])) $key = (string)$h['X-Admin-Key'];
    }
    if ($key === '' || !hash_equals(ADMIN_KEY, $key)) {
        usleep(500000);
        respond(403, ['error' => 'forbidden']);
    }
}

// === Роутинг ===
$action = $_GET['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

switch ($action) {

    case 'response': {
        if ($method !== 'POST') respond(405, ['error' => 'post_only']);
        $body = readJsonBody(MAX_BODY_BYTES);

        // Honeypot: скрытое поле 'website' в анкете должно быть пустым.
        if (!empty($body['website'])) {
            respond(200, ['ok' => true, 'id' => 'hp']);
        }

        // Минимальное время заполнения.
        $fillMs = (int)($body['totalTimeMs'] ?? 0);
        if ($fillMs > 0 && $fillMs < MIN_FILL_MS) {
            respond(200, ['ok' => true, 'id' => 'tt']);
        }

        if (!isset($body['answers']) || !is_array($body['answers'])) {
            respond(400, ['error' => 'invalid_data']);
        }

        checkRateLimit(clientIp(), RATE_LIMIT_PER_MIN);

        $record = [
            'id'          => uniqid('r_', true),
            'submittedAt' => date('c'),
            'ip'          => clientIp(),
            'userAgent'   => substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 300),
            'answers'     => $body['answers'],
            'otherTexts'  => $body['otherTexts'] ?? [],
            'timing'      => $body['timing']     ?? [],
            'meta'        => $body['meta']       ?? [],
            'totalTimeMs' => $fillMs,
        ];
        file_put_contents(
            DATA_DIR . '/responses.jsonl',
            json_encode($record, JSON_UNESCAPED_UNICODE) . "\n",
            FILE_APPEND | LOCK_EX
        );
        respond(200, ['ok' => true, 'id' => $record['id']]);
    }

    case 'contact': {
        if ($method !== 'POST') respond(405, ['error' => 'post_only']);
        $body = readJsonBody(MAX_BODY_BYTES);

        if (!empty($body['website'])) {
            respond(200, ['ok' => true]);
        }

        $email = trim((string)($body['email'] ?? ''));
        if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            respond(400, ['error' => 'invalid_email']);
        }
        if (strlen($email) > 200) {
            respond(400, ['error' => 'email_too_long']);
        }

        checkRateLimit(clientIp(), RATE_LIMIT_PER_MIN);

        $record = [
            'email'       => $email,
            'submittedAt' => date('c'),
            'ip'          => clientIp(),
        ];
        file_put_contents(
            DATA_DIR . '/contacts.jsonl',
            json_encode($record, JSON_UNESCAPED_UNICODE) . "\n",
            FILE_APPEND | LOCK_EX
        );
        respond(200, ['ok' => true]);
    }

    case 'login': {
        if ($method !== 'POST') respond(405, ['error' => 'post_only']);
        checkRateLimit(clientIp(), max(RATE_LIMIT_PER_MIN, 20));
        $body = readJsonBody(4096);
        $key = (string)($body['key'] ?? '');
        if ($key === '' || !hash_equals(ADMIN_KEY, $key)) {
            usleep(500000);
            respond(403, ['error' => 'forbidden']);
        }
        respond(200, ['ok' => true]);
    }

    case 'export': {
        requireAdmin();
        $file = DATA_DIR . '/responses.jsonl';
        if (!file_exists($file)) respond(200, []);
        $lines = array_filter(explode("\n", (string)file_get_contents($file)));
        $data = [];
        foreach ($lines as $line) {
            $d = json_decode($line, true);
            if (is_array($d)) $data[] = $d;
        }
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    }

    case 'export_contacts': {
        requireAdmin();
        $file = DATA_DIR . '/contacts.jsonl';
        if (!file_exists($file)) respond(200, []);
        $lines = array_filter(explode("\n", (string)file_get_contents($file)));
        $data = [];
        foreach ($lines as $line) {
            $d = json_decode($line, true);
            if (is_array($d)) $data[] = $d;
        }
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    }

    case 'stats': {
        requireAdmin();
        $rFile = DATA_DIR . '/responses.jsonl';
        $cFile = DATA_DIR . '/contacts.jsonl';
        $rCount = file_exists($rFile) ? count(array_filter(explode("\n", (string)file_get_contents($rFile)))) : 0;
        $cCount = file_exists($cFile) ? count(array_filter(explode("\n", (string)file_get_contents($cFile)))) : 0;
        respond(200, ['responses' => $rCount, 'contacts' => $cCount]);
    }

    default:
        respond(400, [
            'error' => 'unknown_action',
            'allowed' => ['response', 'contact', 'login', 'export', 'export_contacts', 'stats'],
        ]);
}
