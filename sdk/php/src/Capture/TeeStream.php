<?php

declare(strict_types=1);

namespace TrafficTwin\Capture;

use Psr\Http\Message\StreamInterface;

/**
 * PSR-7 stream decorator that tees the bytes the application (or the response emitter) reads
 * (sanitizer.md 9.0): it keeps a copy of the first `$limit` bytes and counts the rest, without
 * altering what the caller sees. Used for non-seekable bodies; seekable ones are read directly.
 *
 * Parameters are left untyped on purpose so the class implements both psr/http-message 1.x
 * and 2.x.
 */
final class TeeStream implements StreamInterface
{
    private int $pos = 0;
    /** Contiguous high-water mark: bytes 0..hw-1 have been observed. */
    private int $hw = 0;
    private string $prefix = '';
    private bool $gap = false;
    private bool $eofSeen = false;

    public function __construct(private StreamInterface $inner, private int $limit)
    {
        try {
            $this->pos = $inner->isSeekable() ? $inner->tell() : 0;
        } catch (\Throwable) {
            $this->pos = 0;
        }
        $this->hw = $this->pos;
        $this->prefix = '';
        // Bytes before the starting position were never observed.
        $this->gap = $this->pos > 0;
    }

    private function observe(string $data): void
    {
        $n = strlen($data);
        if ($n === 0) {
            return;
        }
        $off = $this->pos;
        $this->pos += $n;
        if ($this->gap || $off > $this->hw) {
            $this->gap = true;
            return;
        }
        if ($off + $n <= $this->hw) {
            return; // read again after a rewind
        }
        $new = $off < $this->hw ? substr($data, $this->hw - $off) : $data;
        $room = $this->limit - strlen($this->prefix);
        if ($room > 0) {
            $this->prefix .= substr($new, 0, $room);
        }
        $this->hw = $off + $n;
    }

    /** First bytes seen (at most $limit). */
    public function prefix(): string
    {
        return $this->prefix;
    }

    /** Total length observed, or null if bytes were skipped (seek ahead) and the length is unknown. */
    public function total(): ?int
    {
        return $this->gap ? null : $this->hw;
    }

    /** True when the stream was read to its end. */
    public function consumed(): bool
    {
        if ($this->gap) {
            return false;
        }
        if ($this->eofSeen) {
            return true;
        }
        try {
            $size = $this->inner->getSize();
            return $size !== null && $this->hw >= $size;
        } catch (\Throwable) {
            return false;
        }
    }

    public function __toString(): string
    {
        try {
            if ($this->isSeekable()) {
                $this->seek(0);
            }
            return $this->getContents();
        } catch (\Throwable) {
            return '';
        }
    }

    public function close(): void
    {
        $this->inner->close();
    }

    public function detach()
    {
        return $this->inner->detach();
    }

    public function getSize(): ?int
    {
        return $this->inner->getSize();
    }

    public function tell(): int
    {
        return $this->inner->tell();
    }

    public function eof(): bool
    {
        $e = $this->inner->eof();
        if ($e) {
            $this->eofSeen = true;
        }
        return $e;
    }

    public function isSeekable(): bool
    {
        return $this->inner->isSeekable();
    }

    public function seek($offset, $whence = SEEK_SET): void
    {
        $this->inner->seek($offset, $whence);
        $this->pos = $this->inner->tell();
    }

    public function rewind(): void
    {
        $this->inner->rewind();
        $this->pos = $this->inner->tell();
    }

    public function isWritable(): bool
    {
        return $this->inner->isWritable();
    }

    public function write($string): int
    {
        return $this->inner->write($string);
    }

    public function isReadable(): bool
    {
        return $this->inner->isReadable();
    }

    public function read($length): string
    {
        $data = $this->inner->read($length);
        $this->observe($data);
        if ($data === '' || $this->inner->eof()) {
            $this->eofSeen = $this->eofSeen || $this->inner->eof();
        }
        return $data;
    }

    public function getContents(): string
    {
        $out = '';
        while (!$this->inner->eof()) {
            $chunk = $this->read(8192);
            if ($chunk === '') {
                break;
            }
            $out .= $chunk;
        }
        $this->eofSeen = $this->eofSeen || $this->inner->eof();
        return $out;
    }

    public function getMetadata($key = null)
    {
        return $this->inner->getMetadata($key);
    }
}
