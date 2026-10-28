using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace TrafficTwin.Sdk.Capture;

/// <summary>
/// Request content that forwards everything to the original content and tees the bytes serialized to the wire.
/// A retry (a second serialization) restarts the tap, so only the last attempt is kept.
/// </summary>
internal sealed class TeeRequestContent : HttpContent
{
    private readonly HttpContent inner;
    private readonly BodyTap tap;

    public TeeRequestContent(HttpContent inner, BodyTap tap)
    {
        this.inner = inner;
        this.tap = tap;
        foreach (var h in inner.Headers.NonValidated)
            Headers.TryAddWithoutValidation(h.Key, (System.Collections.Generic.IEnumerable<string>)h.Value);
    }

    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
        SerializeToStreamAsync(stream, context, CancellationToken.None);

    protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context, CancellationToken cancellationToken)
    {
        tap.Reset();
        await inner.CopyToAsync(new TeeWriteStream(stream, tap), context, cancellationToken).ConfigureAwait(false);
        tap.Ended = true;
    }

    protected override void SerializeToStream(Stream stream, TransportContext? context, CancellationToken cancellationToken)
    {
        tap.Reset();
        inner.CopyTo(new TeeWriteStream(stream, tap), context, cancellationToken);
        tap.Ended = true;
    }

    protected override bool TryComputeLength(out long length)
    {
        long? l = inner.Headers.ContentLength;
        length = l ?? 0;
        return l.HasValue;
    }

    protected override void Dispose(bool disposing)
    {
        // The original content is disposed by its owner (the request restores it after sending).
        base.Dispose(disposing);
    }
}

/// <summary>Response content that streams from the original content and tees the bytes the app reads.</summary>
internal sealed class TeeResponseContent : HttpContent
{
    private readonly HttpContent inner;
    private readonly BodyTap tap;
    private readonly Action<bool> onDone;
    private TeeReadStream? stream;
    private readonly object gate = new();

    public TeeResponseContent(HttpContent inner, BodyTap tap, Action<bool> onDone)
    {
        this.inner = inner;
        this.tap = tap;
        this.onDone = onDone;
        foreach (var h in inner.Headers.NonValidated)
            Headers.TryAddWithoutValidation(h.Key, (System.Collections.Generic.IEnumerable<string>)h.Value);
    }

    private TeeReadStream Wrap(Stream s)
    {
        lock (gate) return stream ??= new TeeReadStream(s, tap, onDone);
    }

    protected override Stream CreateContentReadStream(CancellationToken cancellationToken) => Wrap(inner.ReadAsStream(cancellationToken));

    protected override async Task<Stream> CreateContentReadStreamAsync() => Wrap(await inner.ReadAsStreamAsync().ConfigureAwait(false));

    protected override async Task<Stream> CreateContentReadStreamAsync(CancellationToken cancellationToken) =>
        Wrap(await inner.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false));

    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
        SerializeToStreamAsync(stream, context, CancellationToken.None);

    protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context, CancellationToken cancellationToken)
    {
        Stream src = await CreateContentReadStreamAsync(cancellationToken).ConfigureAwait(false);
        await src.CopyToAsync(stream, cancellationToken).ConfigureAwait(false);
    }

    protected override void SerializeToStream(Stream stream, TransportContext? context, CancellationToken cancellationToken)
    {
        Stream src = CreateContentReadStream(cancellationToken);
        src.CopyTo(stream);
    }

    protected override bool TryComputeLength(out long length)
    {
        long? l = inner.Headers.ContentLength;
        length = l ?? 0;
        return l.HasValue;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            try { onDone(false); }
            catch (Exception) { /* never affects the app */ }
            inner.Dispose();
        }
        base.Dispose(disposing);
    }
}
