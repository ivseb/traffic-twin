<?php

declare(strict_types=1);

// Minimal PSR-4 autoloader for use without Composer (tests of the sanitizer, tt-shipper from a checkout).
spl_autoload_register(static function (string $class): void {
    $prefix = 'TrafficTwin\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $file = __DIR__ . '/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($file)) {
        require $file;
    }
});
