using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace TrafficTwin.Sdk.Capture;

/// <summary>
/// Read-through stream that copies what is read into a <see cref="BodyTap"/>. It forwards every call to the inner stream
/// unchanged (same bytes, same return values, same exceptions); a failure of the tap never reaches the caller.
/// </summary>
internal sealed class TeeReadStream : Stream
{
    private readonly Stream inner;
    private readonly BodyTap tap;
    private readonly Action<bool>? onDone;
    private int done;

    /// <param name="onDone">Called once: <c>true</c> when the end of the stream was read, <c>false</c> when disposed earlier.</param>
    public TeeReadStream(Stream inner, BodyTap tap, Action<bool>? onDone = null)
    {
        this.inner = inner;
        this.tap = tap;
        this.onDone = onDone;
    }

    private void Finish(bool ended)
    {
        if (ended) tap.Ended = true;
        if (Interlocked.Exchange(ref done, 1) == 0)
        {
            try { onDone?.Invoke(ended); }
            catch (Exception) { /* never affects the app */ }
        }
    }

    public override bool CanRead => inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => inner.Length;
    public override long Position { get => inner.Position; set => throw new NotSupportedException(); }
    public override bool CanTimeout => inner.CanTimeout;
    public override int ReadTimeout { get => inner.ReadTimeout; set => inner.ReadTimeout = value; }

    public override int Read(byte[] buffer, int offset, int count)
    {
        int n = inner.Read(buffer, offset, count);
        if (n > 0) tap.Add(buffer.AsSpan(offset, n));
        else if (count > 0) Finish(true);
        return n;
    }

    public override int Read(Span<byte> buffer)
    {
        int n = inner.Read(buffer);
        if (n > 0) tap.Add(buffer.Slice(0, n));
        else if (buffer.Length > 0) Finish(true);
        return n;
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        int n = await inner.ReadAsync(buffer.AsMemory(offset, count), cancellationToken).ConfigureAwait(false);
        if (n > 0) tap.Add(buffer.AsSpan(offset, n));
        else if (count > 0) Finish(true);
        return n;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        int n = await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        if (n > 0) tap.Add(buffer.Span.Slice(0, n));
        else if (buffer.Length > 0) Finish(true);
        return n;
    }

    public override int ReadByte()
    {
        int b = inner.ReadByte();
        if (b >= 0) tap.Add(stackalloc byte[] { (byte)b });
        else Finish(true);
        return b;
    }

    public override void Flush() => inner.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            Finish(false);
            inner.Dispose();
        }
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        Finish(false);
        await inner.DisposeAsync().ConfigureAwait(false);
        await base.DisposeAsync().ConfigureAwait(false);
    }
}

/// <summary>
/// Write-through stream that copies what is written into a <see cref="BodyTap"/> after the inner stream accepted it.
/// Every call is forwarded unchanged.
/// </summary>
internal sealed class TeeWriteStream : Stream
{
    private readonly Stream inner;
    private readonly BodyTap tap;

    public TeeWriteStream(Stream inner, BodyTap tap)
    {
        this.inner = inner;
        this.tap = tap;
    }

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => inner.CanWrite;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override bool CanTimeout => inner.CanTimeout;
    public override int WriteTimeout { get => inner.WriteTimeout; set => inner.WriteTimeout = value; }

    public override void Write(byte[] buffer, int offset, int count)
    {
        inner.Write(buffer, offset, count);
        tap.Add(buffer.AsSpan(offset, count));
    }

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        inner.Write(buffer);
        tap.Add(buffer);
    }

    public override void WriteByte(byte value)
    {
        inner.WriteByte(value);
        tap.Add(stackalloc byte[] { value });
    }

    public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        await inner.WriteAsync(buffer.AsMemory(offset, count), cancellationToken).ConfigureAwait(false);
        tap.Add(buffer.AsSpan(offset, count));
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        await inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        tap.Add(buffer.Span);
    }

    public override void Flush() => inner.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    // The inner stream belongs to the caller of the tee; it is not disposed here.
}
