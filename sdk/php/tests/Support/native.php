<?php

declare(strict_types=1);

// A plain PHP script (no framework, no PSR-7) instrumented with Native::install().
require __DIR__ . '/../../vendor/autoload.php';

\TrafficTwin\Integration\Native::install();

header('Content-Type: application/json');
header('X-Powered-By-Shop: native');
setcookie('sid', '9f8e7d6c5b4a', ['path' => '/', 'httponly' => true]);
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    $in = json_decode((string) file_get_contents('php://input'), true) ?: [];
    http_response_code(201);
    echo json_encode(['id' => 'ORD-2026-000184', 'status' => 'CREATED', 'total' => 73.40, 'echo' => $in['note'] ?? null]);
} else {
    echo json_encode(['status' => 'OK', 'big' => str_repeat('y', 20000)]);
}
