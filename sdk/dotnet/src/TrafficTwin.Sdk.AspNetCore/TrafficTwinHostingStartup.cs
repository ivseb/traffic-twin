using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using TrafficTwin.Sdk;
using TrafficTwin.Sdk.AspNetCore;

[assembly: HostingStartup(typeof(TrafficTwinHostingStartup))]

namespace TrafficTwin.Sdk.AspNetCore;

/// <summary>
/// Zero-code registration for ASP.NET Core: <c>ASPNETCORE_HOSTINGSTARTUPASSEMBLIES=TrafficTwin.Sdk.AspNetCore</c> (the
/// <c>DOTNET_STARTUP_HOOKS</c> assembly makes the runtime find it, see <c>sdk/dotnet/README.md</c>). It does what
/// <c>AddTrafficTwin()</c> + <c>UseTrafficTwin()</c> do in code:
/// an <see cref="Microsoft.AspNetCore.Hosting.IStartupFilter"/> puts <see cref="TrafficTwinMiddleware"/> first in the pipeline, every
/// <c>IHttpClientFactory</c> client gets <see cref="TrafficTwinHandler"/>, and the agent is flushed when the host stops.
/// It does nothing without <c>TT_ENROLL_URL</c> (or with <c>TT_DISABLED=1</c>), and steps aside for what the application
/// registered by hand with <c>AddTrafficTwin()</c>.
/// </summary>
public sealed class TrafficTwinHostingStartup : IHostingStartup
{
    public void Configure(IWebHostBuilder builder)
    {
        TrafficTwinOptions options = TrafficTwinOptions.FromEnvironment();
        if (options.Disabled || string.IsNullOrEmpty(options.EnrollUrl)) return;
        builder.ConfigureServices(services =>
        {
            // The process-wide agent (idempotent: the startup hook already started it when it is present).
            TrafficTwinAgent agent = TrafficTwinAgent.Start(options);
            services.TryAddEnumerable(ServiceDescriptor.Transient<IStartupFilter, TrafficTwinStartupFilter>());
            services.AddHostedService(_ => new FlushOnStop());
            services.ConfigureHttpClientDefaults(b => b.AddHttpMessageHandler(sp =>
                sp.GetService<ExplicitRegistration>() == null ? new TrafficTwinHandler(agent) : new PassThroughHandler()));
        });
    }
}

/// <summary>Registered by <c>AddTrafficTwin()</c>: the application wired the SDK itself, the hosting startup must not add it twice.</summary>
internal sealed class ExplicitRegistration
{
}

internal sealed class TrafficTwinStartupFilter : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        if (app.ApplicationServices.GetService<ExplicitRegistration>() == null) app.UseMiddleware<TrafficTwinMiddleware>();
        next(app);
    };
}

internal sealed class PassThroughHandler : System.Net.Http.DelegatingHandler
{
}

internal sealed class FlushOnStop : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            TrafficTwinAgent? agent = TrafficTwinAgent.Current;
            if (agent == null) return;
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            await agent.FlushAsync().WaitAsync(cts.Token).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // best effort
        }
    }
}
