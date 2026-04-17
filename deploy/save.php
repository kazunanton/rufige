<?php
/**
 * save.php — бэкенд для сохранения ответов анкеты
 *
 * Кладётся рядом с index.html на любой PHP-хостинг.
 * Ответы пишутся в файл data/responses.jsonl (одна строка = один респондент).
 * Контакты — в data/contacts.jsonl.
 *
 * Эндпоинты:
 *   POST /save.php?action=response   — сохранить анкету
 *   POST /save.php?action=contact    — сохранить e-mail для результатов
 *   GET  /save.php?action=export&key=XXX  — скачать все ответы (JSON)
 *   GET  /save.php?action=export_contacts&key=XXX — скачать контакты
 */

// === НАСТРОЙКИ ===
// Измените этот ключ на свой (любая строка). Он нужен для скачивания данных.
define('ADMIN_KEY', 'Hs3_Srv2026_xK9mPq4vR');

// Папка для хранения данных
define('DATA_DIR', __DIR__ . '/data');

// === CORS (чтобы анкета работала, если index.html открыт с другого домена) ===
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// === Создаём папку data, если её нет ===
if (!is_dir(DATA_DIR)) {
    mkdir(DATA_DIR, 0755, true);
    // Защита от прямого доступа к файлам
    file_put_contents(DATA_DIR . '/.htaccess', "Deny from all\n");
}

$action = $_GET['action'] ?? '';

switch ($action) {

    // --- Сохранение ответов анкеты ---
    case 'response':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'POST only']);
            exit;
        }
        $body = json_decode(file_get_contents('php://input'), true);
        if (!$body || !isset($body['answers'])) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid data']);
            exit;
        }
        $record = [
            'id' => uniqid('r_', true),
            'submittedAt' => date('c'),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'userAgent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'answers' => $body['answers'],
            'otherTexts' => $body['otherTexts'] ?? [],
            'timing' => $body['timing'] ?? [],
            'meta' => $body['meta'] ?? [],
            'totalTimeMs' => $body['totalTimeMs'] ?? 0,
        ];
        file_put_contents(
            DATA_DIR . '/responses.jsonl',
            json_encode($record, JSON_UNESCAPED_UNICODE) . "\n",
            FILE_APPEND | LOCK_EX
        );
        echo json_encode(['ok' => true, 'id' => $record['id']]);
        break;

    // --- Сохранение контакта ---
    case 'contact':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'POST only']);
            exit;
        }
        $body = json_decode(file_get_contents('php://input'), true);
        $email = trim($body['email'] ?? '');
        if (!$email) {
            http_response_code(400);
            echo json_encode(['error' => 'No email']);
            exit;
        }
        $record = [
            'email' => $email,
            'submittedAt' => date('c'),
        ];
        file_put_contents(
            DATA_DIR . '/contacts.jsonl',
            json_encode($record, JSON_UNESCAPED_UNICODE) . "\n",
            FILE_APPEND | LOCK_EX
        );
        echo json_encode(['ok' => true]);
        break;

    // --- Экспорт ответов (защищён ключом) ---
    case 'export':
        $key = $_GET['key'] ?? '';
        if ($key !== ADMIN_KEY) {
            http_response_code(403);
            echo json_encode(['error' => 'Invalid key']);
            exit;
        }
        $file = DATA_DIR . '/responses.jsonl';
        if (!file_exists($file)) {
            echo json_encode([]);
            exit;
        }
        $lines = array_filter(explode("\n", file_get_contents($file)));
        $data = array_map(function($line) { return json_decode($line, true); }, $lines);
        header('Content-Disposition: attachment; filename="responses_' . date('Y-m-d') . '.json"');
        echo json_encode(array_values($data), JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        break;

    // --- Экспорт контактов ---
    case 'export_contacts':
        $key = $_GET['key'] ?? '';
        if ($key !== ADMIN_KEY) {
            http_response_code(403);
            echo json_encode(['error' => 'Invalid key']);
            exit;
        }
        $file = DATA_DIR . '/contacts.jsonl';
        if (!file_exists($file)) {
            echo json_encode([]);
            exit;
        }
        $lines = array_filter(explode("\n", file_get_contents($file)));
        $data = array_map(function($line) { return json_decode($line, true); }, $lines);
        header('Content-Disposition: attachment; filename="contacts_' . date('Y-m-d') . '.json"');
        echo json_encode(array_values($data), JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        break;

    // --- Статистика (кол-во ответов) ---
    case 'stats':
        $key = $_GET['key'] ?? '';
        if ($key !== ADMIN_KEY) {
            http_response_code(403);
            echo json_encode(['error' => 'Invalid key']);
            exit;
        }
        $rFile = DATA_DIR . '/responses.jsonl';
        $cFile = DATA_DIR . '/contacts.jsonl';
        $rCount = file_exists($rFile) ? count(array_filter(explode("\n", file_get_contents($rFile)))) : 0;
        $cCount = file_exists($cFile) ? count(array_filter(explode("\n", file_get_contents($cFile)))) : 0;
        echo json_encode(['responses' => $rCount, 'contacts' => $cCount]);
        break;

    default:
        http_response_code(400);
        echo json_encode(['error' => 'Unknown action. Use: response, contact, export, export_contacts, stats']);
}
