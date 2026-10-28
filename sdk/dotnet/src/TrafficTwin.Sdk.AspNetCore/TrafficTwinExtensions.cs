using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using TrafficTwin.Sdk;

namespace TrafficTwin.Sdk.AspNetCore;

public static class TrafficTwinExtensions
{
    /// <summary>
    /// Registers the traffic-twin agent (configured from the environment, then from <paramref name="configure"/>), starts its Fleet cycle
    /// in the background when the host starts (the application never waits for it), and adds <see cref="TrafficTwinHandler"/> to every
    /// <c>IHttpClientFactory</c> client.
    /// </summary>
    public static IServiceCollection AddTrafficTwin(this IServiceCollection services, Action<TrafficTwinOptions>? configure = null)
    {
        var options = TrafficTwinOptions.FromEnvironment();
        configure?.Invoke(options);
        var agent = TrafficTwinAgent.Create(options);
        services.AddSingleton(agent);
        services.AddSingleton<ExplicitRegistration>(); // the hosting startup (zero-code injection) steps aside
        services.AddHostedService(_ => new TrafficTwinHostedService(agent, options));
        services.ConfigureHttpClientDefaults(b => b.AddHttpMessageHandler(_ => new TrafficTwinHandler(agent)));
        return services;
    }

    /// <summary>Adds the inbound capture middleware. Call it first in the pipeline.</summary>
    public static IApplicationBuilder UseTrafficTwin(this IApplicationBuilder app) => app.UseMiddleware<TrafficTwinMiddleware>();
}

/// <summary>Starts the agent without delaying the application start-up, and flushes it on shutdown.</summary>
internal sealed class TrafficTwinHostedService : IHostedService
{
    private readonly TrafficTwinAgent agent;
    private readonly TrafficTwinOptions options;

    public TrafficTwinHostedService(TrafficTwinAgent agent, TrafficTwinOptions options)
    {
        this.agent = agent;
        this.options = options;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (!options.Disabled)
        {
            agent.SetAsCurrent();
            _ = agent.StartAsync();
        }
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            await agent.FlushAsync().WaitAsync(cts.Token).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // best effort
        }
        await agent.DisposeAsync().ConfigureAwait(false);
    }
}
