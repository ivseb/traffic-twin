<?php

declare(strict_types=1);

namespace TrafficTwin\Capture;

/**
 * Local spool of sanitized events: append-only segment files in a directory (0700, files 0600).
 *
 * Workers append one line per event; the shipper (bin/tt-shipper) reads the closed segments,
 * sends them and deletes them. A line is
 *
 *     <tsMs> TAB <trace_id or -> TAB <span_id or -> TAB <policy hash> TAB <event canonical JSON> LF
 *
 * The canonical event is ASCII without raw control characters, so it never contains TAB or LF.
 * Only sanitized events (forms, tokens, permitted values) ever touch the disk.
 *
 * Segments are named seg-<bucket>-<pid>.ndjson where bucket = floor(unix time / segment length).
 * Writers open, lock (flock LOCK_EX), check that the path still points to the file they locked
 * (the shipper renames a segment while holding the lock), write one line and close, so no
 * file handle outlives a request.
 */
final class Spool
{
    public const SUFFIX = '.ndjson';
    private bool $dirReady = false;

    public function __construct(private string $dir, private int $segmentSeconds = 2)
    {
    }

    public function dir(): string
    {
        return $this->dir;
    }

    private function ensureDir(): bool
    {
        if ($this->dirReady) {
            return true;
        }
        // Created 0700, or a pre-existing directory narrowed to 0700; refused if it stays open.
        return $this->dirReady = \TrafficTwin\State\Store::secureDir($this->dir);
    }

    /** Appends one record line (without the trailing newline). Returns false if it could not be written. */
    public function append(string $line): bool
    {
        if (!$this->ensureDir()) {
            return false;
        }
        $path = $this->dir . '/seg-' . intdiv(time(), $this->segmentSeconds) . '-' . getmypid() . self::SUFFIX;
        $data = $line . "\n";
        for ($try = 0; $try < 3; $try++) {
            $old = umask(0077);
            $fh = @fopen($path, 'ab');
            umask($old);
            if ($fh === false) {
                return false;
            }
            if (!flock($fh, LOCK_EX)) {
                fclose($fh);
                return false;
            }
            clearstatcache(true, $path);
            $st = @fstat($fh);
            $cur = @stat($path);
            if ($st === false || $cur === false || $st['ino'] !== $cur['ino']) {
                // The shipper took this segment while we waited for the lock: open it again.
                flock($fh, LOCK_UN);
                fclose($fh);
                continue;
            }
            if (($st['mode'] & 0077) !== 0 && !@chmod($path, 0600)) {
                // A pre-existing segment open to others that we cannot narrow: do not write.
                flock($fh, LOCK_UN);
                fclose($fh);
                return false;
            }
            $ok = fwrite($fh, $data) === strlen($data);
            flock($fh, LOCK_UN);
            fclose($fh);
            return $ok;
        }
        return false;
    }

    /**
     * Shipper side: segments of a past time bucket, oldest first (all of them with $includeCurrent).
     * Taking a segment is safe either way, because claim() holds the file lock and writers that
     * lose the race notice it (see append()); the bucket only keeps the shipper from chasing
     * the file writers are using right now.
     *
     * @return list<string> absolute paths
     */
    public function closedSegments(bool $includeCurrent = false): array
    {
        $cur = intdiv(time(), $this->segmentSeconds) + ($includeCurrent ? 1 : 0);
        $out = [];
        foreach (glob($this->dir . '/seg-*' . self::SUFFIX) ?: [] as $f) {
            if (preg_match('/seg-([0-9]+)-[0-9]+' . preg_quote(self::SUFFIX, '/') . '$/D', $f, $m) === 1 && (int) $m[1] < $cur) {
                $out[] = $f;
            }
        }
        sort($out, SORT_NATURAL);
        return $out;
    }

    /**
     * Shipper side: takes a segment so that no writer appends to it any more (lock, rename to
     * .claimed) and returns its new path. Writers waiting on the lock notice the inode change.
     */
    public function claim(string $segment): ?string
    {
        $fh = @fopen($segment, 'rb');
        if ($fh === false) {
            return null;
        }
        if (!flock($fh, LOCK_EX)) {
            fclose($fh);
            return null;
        }
        $claimed = $segment . '.claimed';
        $ok = @rename($segment, $claimed);
        flock($fh, LOCK_UN);
        fclose($fh);
        return $ok ? $claimed : null;
    }

    /** @return list<string> claimed segments left by a previous shipper run, oldest first */
    public function claimedSegments(): array
    {
        $out = glob($this->dir . '/seg-*' . self::SUFFIX . '.claimed') ?: [];
        sort($out, SORT_NATURAL);
        return $out;
    }

    /** Total size in bytes of all segments (open, closed and claimed). */
    public function size(): int
    {
        $n = 0;
        foreach (glob($this->dir . '/seg-*') ?: [] as $f) {
            $n += (int) @filesize($f);
        }
        return $n;
    }

    /** Deletes every segment (kill switch: the queues are dropped). Returns the number of lines removed. */
    public function clear(): int
    {
        $lines = 0;
        foreach (glob($this->dir . '/seg-*') ?: [] as $f) {
            $lines += self::countLines($f);
            @unlink($f);
        }
        return $lines;
    }

    public static function countLines(string $file): int
    {
        $fh = @fopen($file, 'rb');
        if ($fh === false) {
            return 0;
        }
        $n = 0;
        while (!feof($fh)) {
            $chunk = fread($fh, 65536);
            if ($chunk === false) {
                break;
            }
            $n += substr_count($chunk, "\n");
        }
        fclose($fh);
        return $n;
    }
}
