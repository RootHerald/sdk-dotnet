# RootHerald.AspNetCore

Server-side .NET SDK for Root Herald device attestation. Pure managed C#, with
no native dependencies and no DLL bundling, so single-file publish works without
extra steps.

**Background-Check (server → server).** Your dumb client collects an opaque
evidence blob (no keys, no Root Herald contact) and hands it to *your* server.
Your server uses `RootHeraldBackgroundCheckClient`, authenticated with your
`rh_sk_` secret key, to mint a nonce and submit the evidence for appraisal. The
verdict is computed by Root Herald and returned to your backend; it never
travels through the client.

## Install

```bash
dotnet add package RootHerald.AspNetCore
```

## 30-second integration

```csharp
using System.Text.Json.Nodes;
using RootHerald.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Construct once with your SECRET key (rh_sk_…). Any key without the rh_sk_
// prefix is rejected.
builder.Services.AddSingleton(
    new RootHeraldBackgroundCheckClient(builder.Configuration["RootHerald:SecretKey"]!));

var app = builder.Build();

app.MapPost("/attest", async (HttpContext ctx, RootHeraldBackgroundCheckClient rh) =>
{
    var evidence = await ctx.Request.ReadFromJsonAsync<JsonNode>() ?? new JsonObject();

    // 1) Mint a relay-friendly nonce; hand challenge.Nonce to the client, which
    //    quotes over it and returns the opaque evidence blob.
    var challenge = await rh.IssueChallengeAsync();

    // 2) Submit the evidence and get a verdict.
    var result = await rh.VerifyAsync(evidence,
        new AttestOptions { ChallengeId = challenge.ChallengeId });

    return result.IsAllowed
        ? Results.Json(new { ok = true, verdict = result.Verdict })
        // An un-enrolled / failing device is a verdict, NOT an error.
        : Results.Json(new { ok = false, verdict = result.Verdict }, statusCode: 403);
});

app.Run();
```

`VerifyAsync` returns an `AttestResult` whose `Verdict` is normalised to
`"allow"` / `"deny"` / `"review"` (from the raw `pass`/`fail`/`warn`), with
`IsAllowed` as a convenience. The full server verdict object is available
verbatim as a `JsonNode` on `VerdictData` (including the additive, advisory-only
cohort fields under `device`). Protocol/auth/quota problems raise a typed
`RootHeraldApiException` (`InvalidSecretKeyException`, `UnknownPolicyException`,
`ChallengeException`, `InvalidEvidenceException`, `QuotaExceededException`).

> `IssueChallengeAsync` / `VerifyAsync` are the ABI 3.0 names; `CreateChallengeAsync`
> / `AttestAsync` remain as deprecated aliases.

## One-time device enroll (backend-relayed)

The client emits opaque `EnrollBegin()` / `EnrollComplete()` blobs; this backend
helper relays them with the `rh_sk_` secret:

```csharp
var enroll = await rh.RelayEnrollAsync(enrollRequestBlob); // POST /api/v1/devices/enroll
if (enroll.AlreadyEnrolled)
{
    // device already bound; skip activate, just use enroll.DeviceId
}
else
{
    // hand enroll.Challenge to the client's EnrollComplete, then relay the result
    var activated = await rh.RelayActivateAsync(activationResponse); // POST /api/v1/devices/activate
}
```

## Common patterns

### Ban a device

```csharp
var result = await rh.VerifyAsync(evidence, new AttestOptions { ChallengeId = challenge.ChallengeId });
var deviceId = result.VerdictData["ueid"]?.GetValue<string>();
if (deviceId is not null && await banList.Contains(deviceId))
    return Results.Forbid();
```

## Targets

- .NET 8 (LTS)
- .NET 9

## License

MIT. See [LICENSE](./LICENSE).
