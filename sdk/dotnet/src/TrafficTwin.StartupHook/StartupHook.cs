using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Loader;
using TrafficTwin.Sdk;

/// <summary>
/// Zero-code entry point: <c>DOTNET_STARTUP_HOOKS=/path/TrafficTwin.StartupHook.dll</c> (the runtime requires this exact
/// shape: a type called <c>StartupHook</c>, in the global namespace, with <c>public static void Initialize()</c>).
///
/// It runs before the application's <c>Main</c> and does two things, both only when <c>TT_ENROLL_URL</c> is set and
/// <c>TT_DISABLED</c> is not (dropping the hook into a process never changes it by itself):
/// <list type="number">
/// <item>lets the default load context find the <c>TrafficTwin.*</c> assemblies next to the hook, so the application needs no
/// reference to them (its <c>deps.json</c> knows nothing about them); and</item>
/// <item>starts the process-wide agent (<see cref="TrafficTwinAgent.Start"/>: Fleet cycle in the background, never blocks),
/// whose <c>HttpHandlerDiagnosticListener</c> subscription sees every <c>HttpClient</c> of the process.</item>
/// </list>
/// The inbound middleware and the <c>IHttpClientFactory</c> handler are added by the hosting startup assembly
/// (<c>ASPNETCORE_HOSTINGSTARTUPASSEMBLIES=TrafficTwin.Sdk.AspNetCore</c>), which the runtime then finds through (1).
/// It sets no <c>ActivityListener</c>, no <c>TracerProvider</c>, no propagator and no other process-wide default.
/// </summary>
internal class StartupHook
{
    public static void Initialize()
    {
        try
        {
            if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("TT_ENROLL_URL"))) return;
            if (IsTrue(Environment.GetEnvironmentVariable("TT_DISABLED"))) return;
            string? dir = Path.GetDirectoryName(typeof(StartupHook).Assembly.Location);
            if (string.IsNullOrEmpty(dir)) return;
            // Registered BEFORE anything of the SDK is touched: the SDK types are only referenced from Start().
            AssemblyLoadContext.Default.Resolving += (context, name) => Resolve(dir, context, name);
            Start();
        }
        catch (Exception)
        {
            // Never affect the application: it starts without traffic-twin.
        }
    }

    private static Assembly? Resolve(string dir, AssemblyLoadContext context, AssemblyName name)
    {
        try
        {
            if (name.Name == null || !name.Name.StartsWith("TrafficTwin.", StringComparison.Ordinal)) return null;
            string path = Path.Combine(dir, name.Name + ".dll");
            return File.Exists(path) ? context.LoadFromAssemblyPath(path) : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void Start()
    {
        TrafficTwinAgent.Start();
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            try
            {
                TrafficTwinAgent? a = TrafficTwinAgent.Current;
                if (a != null) a.FlushAsync().Wait(TimeSpan.FromSeconds(3));
            }
            catch (Exception)
            {
                // best effort
            }
        };
    }

    private static bool IsTrue(string? v) => v != null && (v == "1" || v.Equals("true", StringComparison.OrdinalIgnoreCase) || v.Equals("yes", StringComparison.OrdinalIgnoreCase));
}
