<?php

declare(strict_types=1);

namespace TrafficTwin\Tests\Integration;

use PHPUnit\Framework\TestCase;
use TrafficTwin\Tests\Support\Fixture;
use TrafficTwin\Tests\Support\Proc;

/** The package as a consumer installs it: zero runtime dependencies, autoload, vendor/bin/tt-shipper. */
final class PackageTest extends TestCase
{
    public function testInstallsWithNoRuntimeDependenciesAndTheShipperRuns(): void
    {
        $composer = trim((string) shell_exec('command -v composer'));
        if ($composer === '') {
            self::markTestSkipped('composer not available');
        }
        $root = realpath(__DIR__ . '/../..');
        $dir = sys_get_temp_dir() . '/tt-consumer-' . bin2hex(random_bytes(4));
        mkdir($dir);
        // A copy without vendor/ and tests/, as a dist archive would be.
        $pkg = $dir . '/pkg';
        mkdir($pkg);
        foreach (['src', 'bin', 'composer.json'] as $e) {
            shell_exec('cp -R ' . escapeshellarg($root . '/' . $e) . ' ' . escapeshellarg($pkg . '/'));
        }
        file_put_contents($dir . '/composer.json', json_encode([
            'name' => 'acme/shop',
            'repositories' => [['type' => 'path', 'url' => $pkg, 'options' => ['symlink' => false]]],
            'require' => ['traffic-twin/sdk' => '*@dev'],
            'minimum-stability' => 'dev',
            'config' => ['allow-plugins' => false],
        ]));
        [$code, $out] = Proc::run([$composer, 'install', '--no-progress', '--no-interaction', '-d', $dir], [], 180);
        self::assertSame(0, $code, $out);
        $lock = json_decode((string) file_get_contents($dir . '/composer.lock'), true);
        self::assertSame(['traffic-twin/sdk'], array_column($lock['packages'], 'name'), 'no runtime dependency beyond PHP and its extensions');
        self::assertFileExists($dir . '/vendor/bin/tt-shipper');
        [$code, $out] = Proc::run([PHP_BINARY, $dir . '/vendor/bin/tt-shipper', '--version'], [], 30);
        self::assertSame(0, $code, $out);
        self::assertSame('0.1.0', trim($out));
        [$code, $out] = Proc::run([PHP_BINARY, $dir . '/vendor/bin/tt-shipper', '--once'], ['TT_STATE_DIR' => ''], 30);
        self::assertSame(2, $code, 'TT_STATE_DIR is required');
        self::assertStringContainsString('TT_STATE_DIR', $out);
        // The sanitizer is usable straight from the installed package.
        $probe = $dir . '/probe.php';
        file_put_contents($probe, '<?php require __DIR__ . "/vendor/autoload.php"; echo class_exists(TrafficTwin\Sanitizer\Sanitizer::class) ? "ok" : "no";');
        [, $out] = Proc::run([PHP_BINARY, $probe], [], 30);
        self::assertSame('ok', $out);
        Fixture::rmrf($dir);
    }
}
