<?php

declare(strict_types=1);

namespace TrafficTwin\State;

/**
 * Local state of the source: directory 0700, files 0600, atomic replace (write a temporary
 * file in the same directory, then rename). Readers never see a half-written file.
 *
 * A pre-existing directory open to group or others is narrowed to 0700 when this process owns
 * it, and refused otherwise (nothing is written into it): in a writable directory another local
 * user could rename files over status.json, whose signing keys and kill switch workers trust.
 */
final class Store
{
    private bool $secure = false;

    public function __construct(public readonly string $dir)
    {
    }

    /** Creates the directory (0700) or narrows a pre-existing one. False if it is not private. */
    public function ensure(): bool
    {
        return $this->secure || ($this->secure = self::secureDir($this->dir));
    }

    /**
     * Makes $dir a private directory: created 0700 when missing; a pre-existing one with any
     * group/other permission bit is chmod'ed to 0700. Returns false when it cannot be created,
     * cannot be narrowed (owned by another user) or is still open afterwards.
     */
    public static function secureDir(string $dir): bool
    {
        clearstatcache(true, $dir);
        if (!is_dir($dir)) {
            $old = umask(0077);
            try {
                @mkdir($dir, 0700, true);
            } finally {
                umask($old);
            }
            clearstatcache(true, $dir);
            if (!is_dir($dir)) {
                return false;
            }
        }
        $perms = @fileperms($dir);
        if ($perms === false) {
            return false;
        }
        if (($perms & 0077) !== 0) {
            if (!@chmod($dir, 0700)) {
                return false;
            }
            clearstatcache(true, $dir);
            $perms = @fileperms($dir);
            if ($perms === false || ($perms & 0077) !== 0) {
                return false;
            }
        }
        return true;
    }

    public function path(string $name): string
    {
        return $this->dir . '/' . $name;
    }

    public function readText(string $name): ?string
    {
        $t = @file_get_contents($this->path($name));
        return $t === false ? null : $t;
    }

    /** @return array<string, mixed>|null */
    public function readJson(string $name): ?array
    {
        $t = $this->readText($name);
        if ($t === null) {
            return null;
        }
        $v = json_decode($t, true);
        return is_array($v) ? $v : null;
    }

    public function writeText(string $name, string $text): bool
    {
        if (!$this->ensure()) {
            return false;
        }
        $final = $this->path($name);
        $tmp = dirname($final) . '/.' . basename($name) . '.' . getmypid() . '.' . bin2hex(random_bytes(3)) . '.tmp';
        $old = umask(0077);
        try {
            $ok = @file_put_contents($tmp, $text) === strlen($text);
        } finally {
            umask($old);
        }
        if (!$ok) {
            @unlink($tmp);
            return false;
        }
        @chmod($tmp, 0600);
        if (!@rename($tmp, $final)) {
            @unlink($tmp);
            return false;
        }
        return true;
    }

    /** @param array<string, mixed> $v */
    public function writeJson(string $name, array $v): bool
    {
        return $this->writeText($name, json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '{}');
    }

    public function remove(string $name): void
    {
        @unlink($this->path($name));
    }
}
