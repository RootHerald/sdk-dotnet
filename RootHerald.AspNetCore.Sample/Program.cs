using System.Text.Json.Nodes;
using RootHerald.AspNetCore;

// Minimal ASP.NET Core API showing both Root Herald paths:
//   * Badge tier (offline JWT verify): GET /me, gated by attestation JWTs.
//   * Background-Check (server -> server): POST /attest, where the dumb client
//     posts its opaque evidence blob and this server appraises it with the
//     rh_sk_ secret key.
// Run against the local dev stack (Root Herald API on http://localhost) — the
// sample's audience matches the seeded test relying party `plat_test_rp`.

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRootHeraldAuthentication(options =>
{
    options.Issuer = builder.Configuration["RootHerald:Issuer"] ?? "http://localhost";
    options.Audience = builder.Configuration["RootHerald:Audience"] ?? "plat_test_rp";
});

// Background-Check client — uses the rh_sk_ secret key (stays on this server).
var secretKey = builder.Configuration["RootHerald:SecretKey"]
    ?? Environment.GetEnvironmentVariable("ROOTHERALD_SECRET_KEY");
if (!string.IsNullOrEmpty(secretKey))
{
    builder.Services.AddSingleton(new RootHeraldBackgroundCheckClient(secretKey));
}

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RootHeraldAttested",
        policy => policy.RequireRootHerald());
});

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "RootHerald.AspNetCore sample — POST a Bearer JWT to /me, or evidence JSON to /attest");

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

// Diagnostic endpoint: dumps ALL claims as the JwtBearer handler surfaced them.
// Lets us see whether the rootherald_device claim is reaching the principal
// and what shape it has.
app.MapGet("/_diag", (HttpContext ctx) =>
{
    var principal = ctx.User;
    if (principal?.Identity?.IsAuthenticated != true)
        return Results.Json(new { authenticated = false });
    var verdict = ctx.GetRootHeraldVerdict();
    return Results.Json(new
    {
        authenticated = true,
        identityName = principal.Identity?.Name,
        claims = principal.Claims.Select(c => new { c.Type, c.Value }).ToArray(),
        verdictPresent = verdict is not null,
        verdict,
    });
}).RequireAuthorization();

app.MapGet("/me", (HttpContext ctx) =>
{
    var verdict = ctx.GetRootHeraldVerdict();
    if (verdict is null) return Results.Unauthorized();
    return Results.Json(new
    {
        ok = true,
        userId = verdict.UserId,
        audience = verdict.Audience,
        acr = verdict.Acr,
        amr = verdict.Amr,
        expiresAt = verdict.ExpiresAt,
        device = new
        {
            deviceId = verdict.Device.DeviceId,
            verdict = verdict.Device.Verdict,
            earStatus = verdict.Device.EarStatus,
            tpmClass = verdict.Device.TpmClass,
            platform = verdict.Device.Platform,
            attestationType = verdict.Device.AttestationType,
            policyId = verdict.Device.PolicyId,
        }
    });
}).RequireAuthorization("RootHeraldAttested");

app.Run();
