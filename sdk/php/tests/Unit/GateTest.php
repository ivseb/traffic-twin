<?php

declare(strict_types=1);

namespace TrafficTwin\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use TrafficTwin\Config;
use TrafficTwin\Runtime;
use TrafficTwin\Tests\Support\Fixture;

/** policy.md 4: the worker captures only when everything checks out, otherwise it does nothing. */
final class GateTest extends TestCase
{
    public function testOpenWhenEverythingChecksOut(): void
    {
        $f = (new Fixture())->write();
        $rt = $f->runtime();
        self::assertNotNull($rt->sanitizer());
        self::assertSame('capturing', $rt->state());
        self::assertSame('shop-api', $rt->serviceName());
    }

    public function testNoStateDirectoryMeansInert(): void
    {
        $rt = new Runtime(new Config());
        self::assertNull($rt->sanitizer());
        self::assertSame('not_configured', $rt->state());
    }

    public function testDisabled(): void
    {
        $f = (new Fixture())->write();
        $c = $f->config();
        $c->disabled = true;
        self::assertSame('disabled', (new Runtime($c))->state());
    }

    public function testNoStatusFile(): void
    {
        $f = new Fixture();
        self::assertSame('no_status', $f->runtime()->state());
    }

    public function testNoPolicy(): void
    {
        $f = new Fixture();
        $f->writeStatus();
        self::assertSame('no_policy', $f->runtime()->state());
    }

    /** @return iterable<string, array{array<string, mixed>, string}> */
    public static function statusCases(): iterable
    {
        yield 'kill switch' => [['kill' => true], 'killed'];
        yield 'revoked' => [['revoked' => true], 'killed'];
        yield 'no heartbeat yet' => [['heartbeat_ok' => false], 'starting'];
        yield 'never in contact' => [['last_contact' => 0], 'expired_policy'];
        yield 'tt-core unreachable longer than policy_max_age' => [['last_contact' => time() - 90000], 'expired_policy'];
        yield 'min_issued_seq above the policy' => [['min_issued_seq' => 2], 'policy_rejected'];
        yield 'other group' => [['group' => 'billing'], 'policy_rejected'];
        yield 'unknown signing key' => [['signing_keys' => ['other' => 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA']], 'policy_rejected'];
        yield 'no signing keys' => [['signing_keys' => []], 'policy_rejected'];
    }

    /** @param array<string, mixed> $over */
    #[DataProvider('statusCases')]
    public function testStatusFailsClosed(array $over, string $state): void
    {
        $f = new Fixture();
        $f->status = $over + $f->status;
        $f->write();
        $rt = $f->runtime();
        self::assertNull($rt->sanitizer());
        self::assertSame($state, $rt->state());
    }

    public function testExpiredPolicy(): void
    {
        $f = new Fixture();
        $f->write(Fixture::policy(['not_after' => gmdate('Y-m-d\TH:i:s\Z', time() - 5)]));
        self::assertSame('expired_policy', $f->runtime()->state());
    }

    public function testTamperedBodyIsRejected(): void
    {
        $f = (new Fixture())->write();
        $env = json_decode((string) file_get_contents($f->dir . '/policy.envelope.json'), true);
        $body = json_decode(base64_decode(strtr($env['body_b64'], '-_', '+/')), true);
        $body['sampling']['rate_bp'] = 10000;
        $body['global']['request']['headers']['authorization'] = ['action' => 'drop'];
        $env['body_b64'] = rtrim(strtr(base64_encode(json_encode($body)), '+/', '-_'), '=');
        file_put_contents($f->dir . '/policy.envelope.json', json_encode($env));
        self::assertSame('policy_rejected', $f->runtime()->state());
    }

    public function testSignatureFromAnotherKeyIsRejected(): void
    {
        $f = new Fixture();
        $other = sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair());
        file_put_contents($f->dir . '/policy.envelope.json', json_encode($f->envelope(Fixture::policy(), $other)));
        $f->writeStatus();
        self::assertSame('policy_rejected', $f->runtime()->state());
    }

    public function testSchemaViolationIsRejected(): void
    {
        $f = new Fixture();
        $f->write(Fixture::policy(['unexpected' => true]));
        self::assertSame('policy_rejected', $f->runtime()->state());
    }

    public function testReservedHmacDomainIsRejected(): void
    {
        $f = new Fixture();
        $f->write(Fixture::policy(['global' => ['request' => ['headers' => ['x-user' => ['action' => 'hmac', 'domain' => 'subject']]]]]));
        self::assertSame('policy_rejected', $f->runtime()->state());
    }

    public function testGarbageEnvelope(): void
    {
        $f = new Fixture();
        $f->writeStatus();
        file_put_contents($f->dir . '/policy.envelope.json', '{"format":');
        self::assertSame('policy_rejected', $f->runtime()->state());
    }

    public function testKeyProblems(): void
    {
        $f = (new Fixture())->write();
        self::assertSame('key_missing', $f->runtime(null)->state());
        self::assertSame('key_missing', $f->runtime('k1:c2hvcnQ')->state());
        self::assertSame('key_mismatch', $f->runtime('k2:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8')->state());
        $c = $f->config(null);
        $c->hmacKeyFile = $f->dir . '/key';
        file_put_contents($c->hmacKeyFile, Fixture::HMAC_KEY . "\n");
        self::assertSame('capturing', (new Runtime($c))->state());
    }

    public function testAcceptedKidDuringRotation(): void
    {
        $f = new Fixture();
        $f->write(Fixture::policy(['hmac' => ['kid' => 'k2', 'accept_kids' => ['k1'], 'epoch' => '2026-10']]));
        self::assertSame('capturing', $f->runtime()->state());
    }

    public function testKillSwitchIsPickedUpWithinTheMemoWindow(): void
    {
        $f = (new Fixture())->write();
        $rt = $f->runtime();
        self::assertNotNull($rt->sanitizer());
        $f->status['kill'] = true;
        $f->writeStatus();
        $rt->reset();
        self::assertNull($rt->sanitizer());
    }

    public function testSamplingOverrideCanOnlyLower(): void
    {
        $f = new Fixture();
        $f->status['override_bp'] = 0;
        $f->write(Fixture::policy());
        $san = $f->runtime()->sanitizer();
        self::assertNotNull($san);
        self::assertSame(0, $san->rateBp());
        $f->status['override_bp'] = 20000; // out of range: ignored
        $f->write(Fixture::policy(['sampling' => ['rate_bp' => 500, 'trust_baggage' => false, 'propagate_to' => []]]));
        self::assertSame(500, $f->runtime()->sanitizer()?->rateBp());
    }

    public function testWithoutSodiumNothingIsCaptured(): void
    {
        // Only meaningful where sodium is absent; elsewhere the gate is exercised by every other test.
        if (function_exists('sodium_crypto_sign_verify_detached')) {
            self::markTestSkipped('ext-sodium present');
        }
        $f = (new Fixture())->write();
        self::assertSame('sodium_missing', $f->runtime()->state());
    }
}
