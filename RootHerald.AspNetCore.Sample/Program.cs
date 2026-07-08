using System.Text.Json.Nodes;
using RootHerald.AspNetCore;

// Minimal ASP.NET Core API showing the Root Herald Background-Check
// (server -> server) path: POST /attest, where the dumb client posts its opaque
// evidence blob and this server appraises it with the rh_sk_ secret key.
// Run against the local dev stack (Root Herald API on http://localhost).

var builder = WebApplication.CreateBuilder(args);

// Background-Check client — uses the rh_sk_ secret key (stays on this server).
var secretKey = builder.Configuration["RootHerald:SecretKey"]
    ?? Environment.GetEnvironmentVariable("ROOTHERALD_SECRET_KEY");
if (!string.IsNullOrEmpty(secretKey))
{
    builder.Services.AddSingleton(new RootHeraldBackgroundCheckClient(secretKey));
}

var app = builder.Build();

app.MapGet("/", () => "RootHerald.AspNetCore sample — POST evidence JSON to /attest");

// Background-Check (server -> server). The dumb client POSTs its opaque
// evidence blob here; this server appraises it with the rh_sk_ secret key. The
// client never holds a key or calls Root Herald directly.
app.MapPost("/attest", async (HttpContext ctx, RootHeraldBackgroundCheckClient? rh) =>
{
    if (rh is null)
        return Results.Json(new { error = "set RootHerald:SecretKey to enable /attest" }, statusCode: 501);

    var evidence = await ctx.Request.ReadFromJsonAsync<JsonNode>() ?? new JsonObject();
    // 1) mint a nonce; in production hand challenge.Nonce to the client first,
    //    then receive the evidence it produced. Compressed here.
    var challenge = await rh.IssueChallengeAsync();
    // 2) appraise the opaque evidence the client posted.
    var result = await rh.VerifyAsync(evidence, new AttestOptions { ChallengeId = challenge.ChallengeId });
    return result.IsAllowed
        ? Results.Json(new { ok = true, verdict = result.Verdict })
        // An un-enrolled / failing device is a verdict, not an error.
        : Results.Json(new { ok = false, verdict = result.Verdict }, statusCode: 403);
});

app.Run();
