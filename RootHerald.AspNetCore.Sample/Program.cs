using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using RootHerald.AspNetCore;

// Minimal ASP.NET Core API showing the Root Herald Background-Check
// (server -> server) path with a device-bound signing key:
//
//   POST /attest    — the client posts its opaque evidence blob; this server
//                     appraises it with the rh_sk_ secret key and learns the
//                     device's alias.
//   POST /mint-key  — the client posts its MintKey certification; this server
//                     relays it and keeps the certified key's public half.
//   POST /action    — a later request the device signed with that key; checked
//                     locally against the stored public key, no Root Herald call.
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

// Attest. The client POSTs its opaque evidence blob here; this server
// appraises it with the rh_sk_ secret key. The client never holds a key or
// calls Root Herald directly.
app.MapPost("/attest", async (HttpContext ctx, RootHeraldClient? rh) =>
{
    if (rh is null)
        return Results.Json(new { error = "set RootHerald:SecretKey to enable /attest" }, statusCode: 501);

    var evidence = await ctx.Request.ReadFromJsonAsync<JsonNode>() ?? new JsonObject();
    // 1) mint a challenge asking for identity; in production relay
    //    challenge.Challenge to the client first, then receive the evidence it
    //    produced. Compressed here.
    var challenge = await rh.IssueChallengeAsync(new ChallengeOptions { Ask = new[] { Ask.Identity } });
    // 2) appraise the opaque evidence the client posted.
    var result = await rh.VerifyAsync(evidence, new AttestOptions { Nonce = challenge.Nonce });
    if (!result.IsPass || result.DeviceId is null)
        // An un-enrolled / failing device is a verdict, not an error.
        return Results.Json(new { ok = false, verdict = result.Verdict }, statusCode: 403);

    return Results.Json(new { ok = true, verdict = result.Verdict, deviceId = result.DeviceId });
});

// Mint a signing key on the device that just passed /attest. The client
// POSTs its MintKey certification; the private half never left the TPM.
app.MapPost("/mint-key", async (HttpContext ctx, RootHeraldClient? rh) =>
{
    if (rh is null)
        return Results.Json(new { error = "set RootHerald:SecretKey to enable /mint-key" }, statusCode: 501);

    var body = await ctx.Request.ReadFromJsonAsync<MintRequest>();
    if (body is null)
        return Results.Json(new { ok = false }, statusCode: 400);

    // 1) mint a key challenge bound to the device; in production relay
    //    keyChallenge.KeyChallenge to the client first, then receive the
    //    certification it produced. Compressed here.
    var keyChallenge = await rh.IssueKeyChallengeAsync(new KeyChallengeOptions
    {
        Purpose = KeyPurpose.Sign,
        ExpectedDevices = new[] { body.DeviceId },
    });
    // 2) relay the certification and keep the public half.
    var key = await rh.CertifyKeyAsync(keyChallenge.Nonce, body.Certification);
    keys[key.KeyId] = key.Jwk;
    return Results.Json(new { ok = true, keyId = key.KeyId, alg = key.Alg, deviceId = key.DeviceId });
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

/// <param name="DeviceId">The deviceId returned by /attest.</param>
/// <param name="Certification">The client's MintKey output, verbatim.</param>
sealed record MintRequest(string DeviceId, JsonNode Certification);

/// <param name="KeyId">The keyId returned by /mint-key.</param>
/// <param name="Message">The signed bytes, verbatim.</param>
/// <param name="Signature">base64; raw r||s or DER for ES256, the modulus length for RS256.</param>
sealed record SignedAction(string KeyId, string Message, string Signature);
