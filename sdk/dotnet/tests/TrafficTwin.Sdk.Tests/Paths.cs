using System;
using System.IO;

namespace TrafficTwin.Sdk.Tests;

internal static class Paths
{
    /// <summary>The repository's conformance/ directory (TT_CONFORMANCE_DIR, else found by walking up from the test assembly).</summary>
    public static string Conformance()
    {
        string? env = Environment.GetEnvironmentVariable("TT_CONFORMANCE_DIR");
        if (!string.IsNullOrEmpty(env)) return env;
        string? dir = AppContext.BaseDirectory;
        while (dir != null)
        {
            string c = Path.Combine(dir, "conformance", "vectors");
            if (Directory.Exists(c)) return Path.Combine(dir, "conformance");
            dir = Path.GetDirectoryName(dir);
        }
        throw new DirectoryNotFoundException("conformance/ not found; set TT_CONFORMANCE_DIR");
    }
}
