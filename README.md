# Root Herald — .NET SDK

.NET SDK family for [Root Herald](https://rootherald.io) device attestation.

## Packages

| Package | What it does | Where it runs | Status |
|---|---|---|---|
| [`RootHerald.AspNetCore`](./RootHerald.AspNetCore) | Backend SDK. **Background-Check (server → server)** via `RootHeraldClient` — appraise a client-collected evidence blob with your `rh_sk_` secret key and get back a verdict | Backend (any OS .NET runs on) | **Preview** (`0.1.0-preview.1`, not yet on NuGet) |

## Quick start: Background-Check (server → server)

```bash
dotnet add package RootHerald.AspNetCore
```

Your dumb client collects an opaque evidence blob and hands it to *your* server,
which appraises it with Root Herald using your `rh_sk_` secret key. The client
never holds a key or talks to Root Herald.

```csharp
using System.Text.Json.Nodes;
using RootHerald.AspNetCore;

// Construct with your SECRET key (rh_sk_…). Any key without the rh_sk_ prefix
// is rejected.
var rh = new RootHeraldClient(
    Environment.GetEnvironmentVariable("ROOTHERALD_SECRET_KEY")!);

// 1) Mint a relay-friendly nonce; send challenge.Nonce down to the client.
var challenge = await rh.IssueChallengeAsync();

// 2) The client quotes over the nonce and returns an opaque evidence blob
//    (JsonNode); submit it for appraisal.
var result = await rh.VerifyAsync(evidence, new AttestOptions
{
    ChallengeId = challenge.ChallengeId,
    Policy      = "rootherald:builtin:strict-hardware", // optional
});

if (result.IsAllowed) { /* proceed */ }
```

Pure managed C#. No native dependencies. Single-file publish works with no DLL
shipped alongside. See [`RootHerald.AspNetCore/README.md`](./RootHerald.AspNetCore/README.md)
for the full surface (verdict shape, enroll relay, common patterns).

> `IssueChallengeAsync` / `VerifyAsync` are retained as `[Obsolete]` aliases of
> `IssueChallengeAsync` / `VerifyAsync` for backwards compatibility.

## Quick start: Enroll relay (one-time device bootstrap)

The keyless client produces opaque enroll blobs; your backend relays them to Root
Herald with the `rh_sk_` secret. The two-leg handshake is asymmetric: a fresh
device returns a MakeCredential challenge (`201`), an already-bound device
short-circuits (`409`, skip the activate leg).

```csharp
// Leg 1 — relay the client's EnrollBegin() blob.
var enroll = await rh.RelayEnrollAsync(new EnrollRequestBlob
{
    EkPublicKey  = blob.EkPublicKey,   // base64 EK public
    AkPublicArea = blob.AkPublicArea,  // base64 TPM2B_PUBLIC of the AK
    Platform     = "windows",
    EkCertPem    = blob.EkCertPem,     // optional
});

// Hand enroll.Challenge to the client's EnrollComplete(); then relay leg 2.
var activated = await rh.RelayActivateAsync(new EnrollActivationResponse
{
    DeviceId        = enroll.DeviceId,
    DecryptedSecret = clientResult.DecryptedSecret,
});
// activated.DeviceId is the stable id you map to your user.
}
```

An un-enrolled / failing device is a verdict (`"deny"`/`"review"`), **not** an
exception. Only protocol/auth/quota problems throw: `InvalidSecretKeyException`
(401), `UnknownPolicyException` (422), `ChallengeException` (409),
`InvalidEvidenceException` (400), `QuotaExceededException` (429).

## Target frameworks

- `net8.0` (LTS)
- `net9.0`

Both packages multi-target. Major .NET versions are added as they hit LTS.

## Trust chain

For `RootHerald.AspNetCore`: the client-collected evidence is appraised server-side by Root Herald, authenticated by your `rh_sk_` secret key. The verdict is computed by Root Herald and returned to your backend; the client never holds a key or receives a verdict.


## License

MIT. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
