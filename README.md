# Root Herald — .NET SDK

.NET SDK family for [Root Herald](https://rootherald.io) device attestation.

## Packages

| Package | What it does | Where it runs | Status |
|---|---|---|---|
| [`RootHerald.AspNetCore`](./RootHerald.AspNetCore) | Backend SDK. **Background-Check (server → server)** via `RootHeraldBackgroundCheckClient` (appraise a client-collected evidence blob with your `rh_sk_` secret key); **badge tier** offline JWT verify via `AddRootHeraldAuthentication(...)`, `HttpContext.GetRootHeraldVerdict()`, `RequireRootHerald()` | Backend (any OS .NET runs on) | **GA** |
| [`RootHerald.Native`](./RootHerald) | FFI binding to the native client SDK (`RootHerald.dll`/`librootherald.so`/`RootHeraldKit`) — drive TPM attestation from C# desktop apps | Desktop (Win/Linux/macOS) | Preview — see below |

## Quick start — ASP.NET Core (backend verify)

```bash
dotnet add package RootHerald.AspNetCore
```

```csharp
using RootHerald.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRootHeraldAuthentication(o =>
{
    o.Issuer = "https://api.rootherald.io";
    o.Audience = "plat_your_client_id";
});

builder.Services.AddAuthorization(o =>
    o.AddPolicy("RootHeraldAttested", p => p.RequireRootHerald()));

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/me", (HttpContext ctx) =>
    Results.Json(new { device = ctx.GetRootHeraldVerdict()?.Device.DeviceId }))
   .RequireAuthorization("RootHeraldAttested");

app.Run();
```

Pure managed C#. No native dependencies. Single-file publish (`PublishSingleFile=true`) produces a single .exe with no `RootHerald.dll` shipped alongside.

See [`RootHerald.AspNetCore/README.md`](./RootHerald.AspNetCore/README.md) for the full surface (claims, policies, common patterns).

## Quick start — Background-Check (server → server)

Your dumb client collects an opaque evidence blob and hands it to *your* server,
which appraises it with Root Herald using your `rh_sk_` secret key. The client
never holds a key or talks to Root Herald.

```csharp
using System.Text.Json.Nodes;
using RootHerald.AspNetCore;

// Construct with your SECRET key (rh_sk_…). A publishable key (rh_pk_…) is
// rejected — it must never be used server-side.
var rh = new RootHeraldBackgroundCheckClient(
    Environment.GetEnvironmentVariable("ROOTHERALD_SECRET_KEY")!);

// 1) Mint a relay-friendly nonce; send challenge.Nonce down to the client.
var challenge = await rh.CreateChallengeAsync();

// 2) The client quotes over the nonce and returns an opaque evidence blob
//    (JsonNode); submit it for appraisal.
var result = await rh.AttestAsync(evidence, new AttestOptions
{
    ChallengeId = challenge.ChallengeId,
    Policy      = "rootherald:builtin:strict-hardware", // optional
    ReturnToken = true,                                 // optional signed EAT
});

if (result.IsAllowed) { /* proceed; result.Token is verifiable offline */ }
```

An un-enrolled / failing device is a verdict (`"deny"`/`"review"`), **not** an
exception. Only protocol/auth/quota problems throw — `InvalidSecretKeyException`
(401), `UnknownPolicyException` (422), `ChallengeException` (409),
`InvalidEvidenceException` (400), `QuotaExceededException` (429).

## Quick start — Native desktop (preview, deferred)

```bash
dotnet add package RootHerald.Native --prerelease
```

```csharp
using RootHerald;

var client = new RootHeraldClient();
var result = await client.VerifyAsync("ranked-queue");
// result.Verdict, result.DeviceId, result.Token
```

The `RootHerald.Native` package P/Invokes into the platform-native Root Herald SDK shipped by [RootHerald/sdk-native](https://github.com/RootHerald/sdk-native). It bundles the native lib in `runtimes/{rid}/native/` per the standard .NET cross-platform pattern.

**Note:** This package is currently in preview pending cross-platform CI for bundling Linux + macOS runtimes. The Windows runtime is available today.

## Target frameworks

- `net8.0` (LTS)
- `net9.0`

Both packages multi-target. Major .NET versions are added as they hit LTS.

## Trust chain

For `RootHerald.AspNetCore`: token signatures are verified against Root Herald's JWKS at `{Issuer}/.well-known/jwks.json`. The underlying `Microsoft.IdentityModel.Protocols.OpenIdConnect` `ConfigurationManager` handles key rotation and caching automatically.

For `RootHerald.Native`: the native client SDK signs attestation evidence with platform-bound keys (TPM AK on Windows/Linux, Secure Enclave key on macOS). Root Herald verifies server-side; the resulting JWT is signed by Root Herald's JWKS.

## License

MIT. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
