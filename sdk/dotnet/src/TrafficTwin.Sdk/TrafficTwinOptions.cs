using System;
using System.Collections;
using System.Text.RegularExpressions;
using TrafficTwin.Sdk.Sanitizing;

namespace TrafficTwin.Sdk;

/// <summary>Configuration of the SDK. <see cref="FromEnvironment"/> reads the same variables as the other traffic-twin SDKs.</summary>
public sealed class TrafficTwinOptions
{
    /// <summary>Fleet base URL used for enrollment (TT_ENROLL_URL). Always https.</summary>
    public string? EnrollUrl { get; set; }

    /// <summary>Enrollment token <c>tte_&lt;secret&gt;.&lt;pin&gt;</c> (TT_ENROLL_TOKEN).</summary>
    public string? EnrollToken { get; set; }

    /// <summary>Content of the local HMAC key, one or more <c>kid:base64url</c> lines (TT_HMAC_KEY). It never leaves the process.</summary>
    public string? HmacKey { get; set; }

    /// <summary>File holding the HMAC key (TT_HMAC_KEY_FILE).</summary>
    public string? HmacKeyFile { get; set; }

    /// <summary>Service name requested at enrollment (TT_SERVICE_NAME, else OTEL_SERVICE_NAME lowercased). The name used in events is the one assigned by tt-core.</summary>
    public string? ServiceName { get; set; }

    /// <summary>Where certificate, private key and policy cache are kept (TT_STATE_DIR). Default <c>~/.traffic-twin/&lt;id&gt;</c>, directory 0700, files 0600.</summary>
    public string? StateDir { get; set; }

    /// <summary>Informational instance name (TT_INSTANCE, default the machine name).</summary>
    public string? Instance { get; set; }

    /// <summary>Send a CSR at enrollment so the private key never leaves the process (default true; TT_ENROLL_CSR=0 turns it off).</summary>
    public bool UseCsr { get; set; } = true;

    /// <summary>Writes status and error codes (never values) to the standard error (TT_DEBUG).</summary>
    public bool Debug { get; set; }

    /// <summary>TT_DISABLED=1: the SDK does nothing.</summary>
    public bool Disabled { get; set; }

    /// <summary>Overrides of the intervals received from tt-core (tests and benchmarks).</summary>
    public TimeSpan? HeartbeatInterval { get; set; }
    public TimeSpan? PolicyPollInterval { get; set; }
    public TimeSpan? ExportFlushInterval { get; set; }

    /// <summary>Maximum time of one Fleet or intake request.</summary>
    public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(15);

    private static readonly Regex ServiceRe = Re.Full("[a-z0-9][a-z0-9._-]{0,62}");

    public static string? ServiceNameFromEnvironment(Func<string, string?> env)
    {
        string? raw = env("TT_SERVICE_NAME");
        if (string.IsNullOrEmpty(raw)) raw = env("OTEL_SERVICE_NAME");
        if (string.IsNullOrEmpty(raw)) return null;
        var sb = new System.Text.StringBuilder();
        foreach (char c in Utf8Util.AsciiLower(raw))
        {
            sb.Append(c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '.' or '_' or '-' ? c : '-');
        }
        string s = sb.ToString().TrimStart('.', '_', '-');
        if (s.Length > 63) s = s.Substring(0, 63);
        return ServiceRe.IsMatch(s) ? s : null;
    }

    private static TimeSpan? MsEnv(string? v)
    {
        if (string.IsNullOrEmpty(v) || v.Length > 9) return null;
        foreach (char c in v)
        {
            if (c < '0' || c > '9') return null;
        }
        return TimeSpan.FromMilliseconds(Math.Max(100, long.Parse(v, System.Globalization.CultureInfo.InvariantCulture)));
    }

    public static TrafficTwinOptions FromEnvironment() => FromEnvironment(n => Environment.GetEnvironmentVariable(n));

    public static TrafficTwinOptions FromEnvironment(Func<string, string?> env)
    {
        static bool Truthy(string? v) => v != null && (v == "1" || v.Equals("true", StringComparison.OrdinalIgnoreCase) || v.Equals("yes", StringComparison.OrdinalIgnoreCase) || v.Equals("debug", StringComparison.OrdinalIgnoreCase));
        return new TrafficTwinOptions
        {
            EnrollUrl = env("TT_ENROLL_URL"),
            EnrollToken = env("TT_ENROLL_TOKEN"),
            HmacKey = env("TT_HMAC_KEY"),
            HmacKeyFile = env("TT_HMAC_KEY_FILE"),
            ServiceName = ServiceNameFromEnvironment(env),
            StateDir = env("TT_STATE_DIR"),
            Instance = env("TT_INSTANCE"),
            UseCsr = env("TT_ENROLL_CSR") != "0",
            Debug = Truthy(env("TT_DEBUG")),
            Disabled = Truthy(env("TT_DISABLED")),
            HeartbeatInterval = MsEnv(env("TT_HEARTBEAT_INTERVAL_MS")),
            PolicyPollInterval = MsEnv(env("TT_POLICY_POLL_INTERVAL_MS")),
            ExportFlushInterval = MsEnv(env("TT_EXPORT_FLUSH_MS")),
        };
    }
}
