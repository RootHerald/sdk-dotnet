# RootHerald.AspNetCore

ASP.NET Core authentication for Root Herald device attestation tokens. Pure managed C#, with no native dependencies and no DLL bundling, so single-file publish works without extra steps.

## Install

```bash
dotnet add package RootHerald.AspNetCore
```

## 30-second integration

```csharp
using RootHerald.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRootHeraldAuthentication(options =>
{
    options.Issuer = "https://api.rootherald.io";       // or your custom-domain endpoint
    options.Audience = "plat_your_client_id";           // your Root Herald RP client_id
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RootHeraldAttested",
        policy => policy.RequireRootHerald());
});

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/me", (HttpContext ctx) =>
{
    var verdict = ctx.GetRootHeraldVerdict();
    return Results.Json(new
    {
        deviceId = verdict?.Device.DeviceId,
        tpmClass = verdict?.Device.TpmClass,
        verdict  = verdict?.Device.Verdict,
        acr      = verdict?.Acr,
    });
}).RequireAuthorization("RootHeraldAttested");

app.Run();
```

That's it. The SDK handles JWKS fetching, key rotation, signature validation, issuer/audience/expiry checks, and parses the nested device claims into a typed object.

## What you get on `HttpContext`

```csharp
RootHeraldVerdict? verdict = HttpContext.GetRootHeraldVerdict();

verdict.UserId            // "fc67877a-3327-8753-9b50-0a69cc1fbba3"
verdict.Audience          // "plat_your_client_id"
verdict.Acr               // "urn:rootherald:user:1fa"
verdict.Amr               // ["pwd"]
verdict.ExpiresAt         // DateTimeOffset

verdict.Device.DeviceId         // stable per-tenant device id
verdict.Device.Verdict          // "pass" | "warn" | "fail"
verdict.Device.EarStatus        // "affirming" | "warning" | "contraindicated"
verdict.Device.TpmClass         // "firmware-tpm-amd-ftpm", etc.
verdict.Device.Platform         // "windows" | "linux" | "macos" | "android" | "ios"
verdict.Device.PolicyId         // applied acceptance policy
verdict.Device.AttestationType  // "tpm20" | "apple-se" | "android-ka" | "ios-appattest"
```

## Common patterns

### Ban a device

```csharp
app.MapPost("/login", async (HttpContext ctx, IBanList banList) =>
{
    var verdict = ctx.GetRootHeraldVerdict()!;
    if (await banList.Contains(verdict.Device.DeviceId))
        return Results.Forbid();
    // ...
}).RequireAuthorization("RootHeraldAttested");
```

### Reject emulators / software TPMs

```csharp
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("HardwareOnly", policy =>
    {
        policy.RequireRootHerald();
        policy.RequireAssertion(ctx =>
        {
            var v = (ctx.Resource as HttpContext)?.GetRootHeraldVerdict();
            return v?.Device.TpmClass?.StartsWith("hardware") == true
                || v?.Device.TpmClass?.StartsWith("firmware-tpm") == true;
        });
    });
});
```

### Step up on stale attestation

```csharp
app.MapPost("/wire-money", (HttpContext ctx) =>
{
    var v = ctx.GetRootHeraldVerdict()!;
    var age = DateTimeOffset.UtcNow - v.Device.AttestedAt;
    if (age > TimeSpan.FromMinutes(2))
        return Results.StatusCode(401);  // force re-attest
    // ...
}).RequireAuthorization("RootHeraldAttested");
```

## Configuration reference

| Option | Default | What it controls |
|---|---|---|
| `Issuer` (required) | — | The Root Herald URL. Tokens whose `iss` doesn't match are rejected. |
| `Audience` (required) | — | Your `client_id`. Tokens whose `aud` doesn't match are rejected. |
| `ClockSkew` | 30 seconds | Tolerance applied to `exp`/`nbf` checks. Set `TimeSpan.Zero` for strict mode. |
| `Scheme` | `"RootHerald"` | Authentication scheme name. Change only if you have multiple JwtBearer handlers. |
| `SetAsDefaultScheme` | `true` | If false, RootHerald is registered but not made the app default; useful when you also have cookie auth for non-API routes. |

## Targets

- .NET 8 (LTS)
- .NET 9

## Trust chain

The SDK's signature verification chains end-to-end to Root Herald's signing key, which is published at `{Issuer}/.well-known/jwks.json`. Token rotation is handled automatically by the underlying `Microsoft.IdentityModel.Protocols.OpenIdConnect` `ConfigurationManager`, which refreshes the JWKS every hour by default.

See [docs/architecture/contracts/attestation-claims.md](https://github.com/rootherald/platform/blob/main/docs/architecture/contracts/attestation-claims.md) for the full claim schema this SDK parses.

## License

MIT. See [LICENSE](./LICENSE).
