<?php

// The external carrier API (invented): POST /v1/shipments.
header('Content-Type: application/json');
$in = json_decode((string) file_get_contents('php://input'), true) ?: [];
http_response_code(201);
echo json_encode(['shipmentId' => 'SHP-' . substr(md5((string) ($in['orderId'] ?? '')), 0, 8), 'status' => 'CREATED']);
