using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using RootHerald.AspNetCore;

// Minimal ASP.NET Core API showing the Root Herald Background-Check
// (server -> server) path with a device-bound signing key:
//
//   POST /attest  — the dumb client posts its opaque evidence blob; this server
//                   appraises it with the rh_sk_ secret key and keeps the
//                   certified key's public half.
//   POST /action  — a later request the device signed with that key; checked
//                   locally against the stored public key, no Root Herald call.
//
// Run against the local dev stack (Root Herald API on http://localhost).

var builder = WebApplication.CreateBuilder(args);

// Background-Check client — uses the rh_sk_ secret key (stays on this server).
var secretKey = builder.Configuration["RootHerald:SecretKey"]
    ?? Environment.GetEnvironmentVariable("ROOTHERALD_SECRET_KEY");
if (!string.IsNullOrEmpty(secretKey))
{
    builder.Services.AddSingleton(new RootHeraldClient(secretKey));
}

// Stands in for the user store: the public key Root Herald certified, kept
// against the key id the device presents later.
var keys = new ConcurrentDictionary<string, JsonObject>();

var app = builder.Build();

app.MapGet("/", () => "RootHerald.AspNetCore sample — POST evidence JSON to /attest");

// Background-Check (server -> server). The dumb client POSTs its opaque
// evidence blob here; this server appraises it with the rh_sk_ secret key. The
// client never holds a key or calls Root Herald directly.
app.MapPost("/attest", async (HttpContext ctx, RootHeraldClient? rh) =>
{
    if (rh is null)
        return Results.Json(new { error = "set RootHerald:SecretKey to enable /attest" }, statusCode: 501);

    var evidence = await ctx.Request.ReadFromJsonAsync<JsonNode>() ?? new JsonObject();
    // 1) mint a challenge asking for identity plus a signing key; in production
    //    relay challenge.Challenge to the client first, then receive the
    //    evidence it produced. Compressed here.
    var challenge = await rh.IssueChallengeAsync(new ChallengeOptions
    {
        Ask = new[] { Ask.Identity, Ask.Key },
        KeyPurpose = "sign",
    });
    // 2) appraise the opaque evidence the client posted.
    var result = await rh.VerifyAsync(evidence, new AttestOptions { Nonce = challenge.Nonce });
    if (!result.IsAllowed || result.Key is null)
        // An un-enrolled / failing device is a verdict, not an error. A passing
        // verdict with a key ask always carries the key.
        return Results.Json(new { ok = false, verdict = result.Verdict }, statusCode: 403);

    // 3) keep the public half; the private half never left the TPM.
    keys[result.Key.KeyId] = result.Key.Jwk;
    return Results.Json(new { ok = true, verdict = result.Verdict, keyId = result.Key.KeyId });
});

// A follow-up request the device signed with its certified key. The signature
// covers the raw message bytes; nothing here calls Root Herald.
app.MapPost("/action", async (HttpContext ctx) =>
{
    var body = await ctx.Request.ReadFromJsonAsync<SignedAction>();
    if (body is null || !keys.TryGetValue(body.KeyId, out var jwk))
        return Results.Json(new { ok = false }, statusCode: 403);

    byte[] signature;
    try { signature = Convert.FromBase64String(body.Signature); }
    catch (FormatException) { return Results.Json(new { ok = false }, statusCode: 403); }

    return RootHeraldClient.VerifyKeySignature(jwk, System.Text.Encoding.UTF8.GetBytes(body.Message), signature)
        ? Results.Json(new { ok = true })
        : Results.Json(new { ok = false }, statusCode: 403);
});

app.Run();

/// <param name="KeyId">The keyId returned by /attest.</param>
/// <param name="Message">The signed bytes, verbatim.</param>
/// <param name="Signature">base64; raw r||s or DER.</param>
sealed record SignedAction(string KeyId, string Message, string Signature);
