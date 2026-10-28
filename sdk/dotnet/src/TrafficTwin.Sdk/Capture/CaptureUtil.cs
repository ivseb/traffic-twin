using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Threading.Tasks;
using TrafficTwin.Sdk.Sanitizing;

namespace TrafficTwin.Sdk.Capture;

internal static class CaptureUtil
{
    /// <summary>Request option set on requests the SDK itself sends (exporter, Fleet): they are never captured.</summary>
    public static readonly HttpRequestOptionsKey<bool> InternalKey = new("traffic-twin.internal");

    /// <summary>Request option set once a request is handled by <see cref="TrafficTwinHandler"/> (the diagnostics observer skips it).</summary>
    public static readonly HttpRequestOptionsKey<bool> HandledKey = new("traffic-twin.handled");

    public static void AddHeaders(List<(string, byte[])> dst, HttpHeaders? headers)
    {
        if (headers == null) return;
        foreach (var h in headers.NonValidated)
        {
            foreach (string v in h.Value)
                dst.Add((h.Key, Utf8Util.Latin1(v)));
        }
    }

    /// <summary>Splits an absolute URI into raw path and raw query bytes (query null without "?"), from the string the app gave.</summary>
    public static (byte[] Path, byte[]? Query) SplitUri(Uri uri)
    {
        string s = uri.IsAbsoluteUri ? uri.OriginalString : uri.OriginalString;
        // Strip "scheme://authority".
        int sc = s.IndexOf("://", StringComparison.Ordinal);
        string rest;
        if (sc >= 0 && uri.IsAbsoluteUri)
        {
            int slash = s.IndexOfAny(new[] { '/', '?', '#' }, sc + 3);
            rest = slash < 0 ? "/" : s.Substring(slash);
            if (rest.Length > 0 && rest[0] != '/') rest = "/" + rest;
        }
        else
        {
            rest = s;
        }
        int hash = rest.IndexOf('#');
        if (hash >= 0) rest = rest.Substring(0, hash);
        int q = rest.IndexOf('?');
        if (q < 0) return (Utf8Util.Latin1(rest), null);
        return (Utf8Util.Latin1(rest.Substring(0, q)), Utf8Util.Latin1(rest.Substring(q + 1)));
    }

    /// <summary>"scheme://host[:port]" as seen by the source (sanitizer.md 1, not normalized).</summary>
    public static string UrlBase(Uri uri)
    {
        // Spec v1.5 (point 9): the host as the client sees it. Uri.Host keeps the brackets of an IPv6 literal, a final dot and a
        // Unicode name as written (IdnHost would convert it); the sanitizer decides what is valid.
        string host = uri.Host;
        bool def = uri.IsDefaultPort;
        return uri.Scheme + "://" + host + (def ? "" : ":" + uri.Port.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    /// <summary>Maps a failure to the event enum (event.md).</summary>
    public static string NetErrorOf(Exception? e)
    {
        for (int depth = 0; e != null && depth < 8; depth++, e = e.InnerException)
        {
            switch (e)
            {
                case TimeoutException:
                    return "timeout";
                case OperationCanceledException:
                    // HttpClient.Timeout (and a caller's cancellation) reach a handler as a canceled token; the usual cause is a timeout.
                    return "timeout";
                case AuthenticationException:
                    return "tls";
                case SocketException se:
                    switch (se.SocketErrorCode)
                    {
                        case SocketError.TimedOut: return "timeout";
                        case SocketError.ConnectionRefused: return "refused";
                        case SocketError.HostNotFound:
                        case SocketError.TryAgain:
                        case SocketError.NoData:
                        case SocketError.NoRecovery: return "dns";
                        case SocketError.ConnectionReset:
                        case SocketError.ConnectionAborted:
                        case SocketError.Shutdown: return "reset";
                    }
                    break;
                case HttpRequestException hre:
                    switch (hre.HttpRequestError)
                    {
                        case HttpRequestError.NameResolutionError: return "dns";
                        case HttpRequestError.SecureConnectionError: return "tls";
                        case HttpRequestError.ConnectionError:
                            if (hre.InnerException is SocketException) break;
                            return "other";
                    }
                    break;
                case IOException when e.InnerException is SocketException:
                    break;
            }
        }
        return "other";
    }

    /// <summary>Adds <c>tt.s</c> to a baggage header value without touching the other members.</summary>
    public static string WithTtS(string? existing, bool sampled)
    {
        string member = "tt.s=" + (sampled ? "1" : "0");
        if (string.IsNullOrWhiteSpace(existing)) return member;
        return existing + "," + member;
    }

    public static long NowMs() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
}
