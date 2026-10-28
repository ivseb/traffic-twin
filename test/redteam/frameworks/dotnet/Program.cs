// Red team round 3: ASP.NET Core minimal API. traffic-twin is attached only through
// DOTNET_STARTUP_HOOKS + ASPNETCORE_HOSTINGSTARTUPASSEMBLIES (zero-code); the app has no
// reference to any TrafficTwin assembly and never logs request data itself.
using System.Text.Json.Nodes;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
builder.Logging.AddSimpleConsole();
var app = builder.Build();

app.MapGet("/health", () => Results.Text("ok"));

app.MapPost("/orders/{id}", async (string id, HttpContext ctx) =>
{
    var b = await JsonNode.ParseAsync(ctx.Request.Body) as JsonObject ?? new JsonObject();
    var secret = b["secret"]?.GetValue<string>();
    ctx.Response.Headers["x-echo"] = ctx.Request.Headers["x-secret"].ToString();
    ctx.Response.Cookies.Append("sess", secret ?? "");
    var email = (b["nested"] as JsonObject)?["email"]?.GetValue<string>();
    return Results.Json(new { id, status = "created", echo = secret, email }, statusCode: 201);
});

app.MapGet("/fail/{v}", (string v) =>
    Results.Json(new { error = new { code = "E_FAIL", message = $"order {v} failed" } }, statusCode: 500));

// Unhandled: Kestrel answers 500 and logs the exception (the app's own log).
app.MapGet("/boom/{v}", (string v) => { throw new InvalidOperationException($"boom {v}"); });

app.Run("http://0.0.0.0:8080");
