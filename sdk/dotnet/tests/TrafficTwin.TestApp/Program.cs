using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

// A shop API as an application writes it: no traffic-twin anywhere.
WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
builder.Services.AddHttpClient("carrier");
WebApplication app = builder.Build();

// No logger: with one, ASP.NET Core itself starts an Activity per request and HttpClient propagates it (not our doing).
app.Lifetime.ApplicationStarted.Register(() =>
{
    foreach (string a in app.Services.GetRequiredService<Microsoft.AspNetCore.Hosting.Server.IServer>().Features.Get<Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>()!.Addresses)
        Console.WriteLine("Now listening on: " + a);
});

string carrier = Environment.GetEnvironmentVariable("CARRIER_URL") ?? "http://127.0.0.1:1";

app.MapPost("/orders", async (HttpContext ctx, IHttpClientFactory f) =>
{
    using var reader = new System.IO.StreamReader(ctx.Request.Body, Encoding.UTF8);
    string body = await reader.ReadToEndAsync();
    HttpClient http = f.CreateClient("carrier");
    HttpResponseMessage res = await http.PostAsync(carrier + "/v1/shipments",
        new StringContent("{\"orderId\":\"ORD-2026-000184\",\"to\":\"giulia.neri@example.com\"}", Encoding.UTF8, "application/json"));
    string shipment = await res.Content.ReadAsStringAsync();
    return Results.Json(new { id = "ORD-2026-000184", status = "CREATED", echo = body.Length, carrierAnswered = shipment.Contains("SHP-7781203") }, statusCode: 201);
});

// An HttpClient that did not come from the factory: seen through the diagnostics listener only.
app.MapGet("/plain", async () =>
{
    using var http = new HttpClient();
    HttpResponseMessage res = await http.PostAsync(carrier + "/v1/shipments", new StringContent("{\"orderId\":\"ORD-2026-000184\"}", Encoding.UTF8, "application/json"));
    return Results.Text(((int)res.StatusCode).ToString());
});

app.MapGet("/health", () => "ok");
app.Run();

public partial class Program
{
}
