using System;

namespace TrafficTwin.Sdk.Capture;

/// <summary>
/// Body tee (sanitizer.md 9.0): keeps a copy of the first <c>limit</c> bytes and counts the rest. Never alters the bytes it
/// sees and copies only what it keeps. All members are safe to call from one producer thread at a time.
/// </summary>
internal sealed class BodyTap
{
    private byte[] buf = Array.Empty<byte>();
    private int kept;
    private readonly int limit;
    private readonly object gate = new();

    public long Total { get; private set; }
    public bool Ended { get; set; }

    public BodyTap(long limit)
    {
        this.limit = (int)Math.Min(limit, int.MaxValue / 2);
    }

    /// <summary>Records bytes; never throws.</summary>
    public void Add(ReadOnlySpan<byte> chunk)
    {
        try
        {
            lock (gate)
            {
                Total += chunk.Length;
                if (kept >= limit || chunk.Length == 0) return;
                int take = Math.Min(chunk.Length, limit - kept);
                if (buf.Length < kept + take)
                {
                    int cap = Math.Min(limit, Math.Max(kept + take, Math.Max(256, buf.Length * 2)));
                    Array.Resize(ref buf, cap);
                }
                chunk.Slice(0, take).CopyTo(buf.AsSpan(kept));
                kept += take;
            }
        }
        catch (Exception)
        {
            // Capturing must never affect the app.
        }
    }

    /// <summary>Forgets everything (a retried request body starts again).</summary>
    public void Reset()
    {
        lock (gate)
        {
            kept = 0;
            Total = 0;
            Ended = false;
        }
    }

    public byte[] Bytes()
    {
        lock (gate)
        {
            return buf.AsSpan(0, kept).ToArray();
        }
    }
}
