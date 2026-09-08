# Root Herald — .NET SDK

.NET SDK family for [Root Herald](https://rootherald.io) device attestation.

## Packages

| Package | What it does | Where it runs | Status |
|---|---|---|---|
| [`RootHerald.AspNetCore`](./RootHerald.AspNetCore) | Backend SDK. **Background-Check (server → server)** via `RootHeraldClient` — appraise a client-collected evidence blob with your `rh_sk_` secret key and get back a verdict | Backend (any OS .NET runs on) | **Preview** (`0.1.0-preview.2`, not yet on NuGet) |

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

// 1) Mint a challenge; relay challenge.Challenge down to the client verbatim.
var challenge = await rh.IssueChallengeAsync();

// 2) The client quotes over the nonce inside it and returns an opaque evidence
//    blob (JsonNode); submit it for appraisal.
var result = await rh.VerifyAsync(evidence, new AttestOptions
{
    ChallengeId = challenge.ChallengeId,
    Policy      = "rootherald:builtin:strict-hardware", // optional
});

if (result.IsAllowed) { /* proceed */ }
```

Pure managed C#. No native dependencies. Single-file publish works with no DLL
shipped alongside. See [`RootHerald.AspNetCore/README.md`](./RootHerald.AspNetCore/README.md)
for the full surface: the verdict shape, the ask model and device-bound
signing keys, the enroll relay, and common patterns.

## Quick start: Enroll relay (one-time device bootstrap)

The keyless client produces opaque enroll blobs; your backend relays them to Root
Herald with the `rh_sk_` secret. Enrollment always issues a MakeCredential
challenge (`201`), including for a device already known — re-enrollment is how a
device rotates its attestation key — so both legs always run.

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
```

An un-enrolled / failing device is a verdict (`"deny"`/`"review"`), **not** an
exception. Only protocol/auth/quota problems throw: `InvalidSecretKeyException`
(401), `UnknownPolicyException` / `PolicyDowngradeException` /
`AdmissionRefusedException` (422, told apart by `ErrorCode`),
`ChallengeException` (409), `InvalidEvidenceException` (400),
`QuotaExceededException` (429).

## Target frameworks

- `net8.0` (LTS)
- `net9.0`

Major .NET versions are added as they hit LTS.

## Trust chain

For `RootHerald.AspNetCore`: the client-collected evidence is appraised server-side by Root Herald, authenticated by your `rh_sk_` secret key. The verdict is computed by Root Herald and returned to your backend; the client never holds a key or receives a verdict.


## License

MIT. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
