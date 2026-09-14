# RootHerald.AspNetCore

Server-side .NET SDK for Root Herald device attestation. Pure managed C#, with
no native dependencies and no DLL bundling, so single-file publish works without
extra steps.

**Background-Check (server → server).** Your dumb client collects an opaque
evidence blob (no keys, no Root Herald contact) and hands it to *your* server.
Your server uses `RootHeraldClient`, authenticated with your `rh_sk_` secret
key, to mint a challenge and submit the evidence for appraisal. The verdict is
computed by Root Herald and returned to your backend; it never travels through
the client.

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
    new RootHeraldClient(builder.Configuration["RootHerald:SecretKey"]!));

var app = builder.Build();

app.MapPost("/attest", async (HttpContext ctx, RootHeraldClient rh) =>
{
    var evidence = await ctx.Request.ReadFromJsonAsync<JsonNode>() ?? new JsonObject();

    // 1) Mint a challenge; relay challenge.Challenge to the client verbatim. It
    //    quotes over the nonce inside it and returns the opaque evidence blob.
    var challenge = await rh.IssueChallengeAsync();

    // 2) Submit the evidence with the nonce and get a verdict.
    var result = await rh.VerifyAsync(evidence,
        new AttestOptions { Nonce = challenge.Nonce });

    return result.IsAllowed
        ? Results.Json(new { ok = true, verdict = result.Verdict })
        // An un-enrolled / failing device is a verdict, NOT an error.
        : Results.Json(new { ok = false, verdict = result.Verdict }, statusCode: 403);
});

app.Run();
```

`VerifyAsync` returns an `AttestResult` whose `Verdict` is normalised to
`"allow"` / `"deny"` / `"review"` (from the raw `pass`/`fail`/`warn`), with
`IsAllowed` as a convenience and `DeviceId` reading `verdict.device.ueid`. The
full server verdict object is available verbatim as a `JsonNode` on
`VerdictData` (including the additive, advisory-only cohort fields under
`device`). Protocol/auth/quota problems raise a typed `RootHeraldApiException`
(`InvalidSecretKeyException`, `UnknownPolicyException`,
`AdmissionRefusedException`, `ChallengeException`, `InvalidEvidenceException`,
`QuotaExceededException`), each exposing the server's `ErrorCode`.

## The challenge carries the ask

`IssueChallengeAsync()` asks for identity and posture. The `ChallengeOptions`
overload sets the ask explicitly. The result carries `Challenge`, the `rhc1.`
string the device answers, and `Nonce`, the backend's handle for it: the
server finds the challenge by the nonce the proof was made over, so `Nonce` is
what `VerifyAsync` takes.

Policies bind to your API key, not to calls. The key carries an identity
policy and, on Pro, a posture policy; a posture ask runs under the posture
policy and everything else under the identity policy. The resolved policy is
pinned on the challenge when it is minted. Change what a key enforces from the
dashboard or `PUT /api/v1/admin/api-keys/{id}/policies`; a `policy` field in a
hand-built request body is refused with `400 policy_bound_to_key`.
`UnknownPolicyException` (422 `unknown_policy`) means a policy bound to the key
no longer exists; nothing is substituted.

Asking for `Ask.Key` has the device create a TPM-resident signing key and
certify it with its attestation key. A passing verdict then carries the public
half as `result.Key`; store it against the user and check later requests
locally, with no call to Root Herald:

```csharp
var challenge = await rh.IssueChallengeAsync(new ChallengeOptions
{
    Ask = new[] { Ask.Identity, Ask.Key },
    KeyPurpose = "sign",
});
var result = await rh.VerifyAsync(evidence, new AttestOptions { Nonce = challenge.Nonce });
if (result.IsAllowed && result.Key is { } key)
    await store.SaveAsync(userId, key.KeyId, key.Jwk); // P-256 or P-384 public key as a JWK

// On a later request the device signed with that key. The signature is ECDSA
// over SHA-256(message) (SHA-384 for P-384), raw r||s or DER; a malformed one
// is false, never an exception.
if (!RootHeraldClient.VerifyKeySignature(jwk, message, signature))
    return Results.Forbid();
```

## One-time device enroll (backend-relayed)

The client emits opaque `EnrollBegin()` / `EnrollComplete()` blobs; this backend
helper relays them with the `rh_sk_` secret. Enrollment always issues a
challenge, including for a device already known — re-enrollment is how a device
rotates its attestation key — so every enroll is followed by activate:

```csharp
var enroll = await rh.RelayEnrollAsync(enrollRequestBlob); // POST /api/v1/attest/enroll
// hand enroll.Challenge to the client's EnrollComplete verbatim, then relay its output
var activated = await rh.RelayActivateAsync(activationResponse); // POST /api/v1/attest/activate
// activated.DeviceId is your alias for the device; it never goes back to the device.
```

`EnrollRequestBlob.Platform` discriminates: `"windows"` / `"linux"` / `"macos"`
carry `EkPublicKey` and `AkPublicArea`; `"ios"` carries `IosKeyId`,
`IosAttestationObject` and `Nonce`, the server answers `{}`, `enroll.Challenge`
is null and there is no activate leg. The activation challenge names the open
enrollment by `EnrollmentId`; the device's `EnrollComplete` output echoes it
with `DecryptedSecret` (TPM) or `Signature` (macOS). No identifier the server
assigns reaches the device.

Admission runs under the key's identity policy, so a device whose TPM class can
never satisfy it is refused before it gets an attestation key:
`AdmissionRefusedException`, with the class in the message.

## Common patterns

### Ban a device

```csharp
var result = await rh.VerifyAsync(evidence, new AttestOptions { Nonce = challenge.Nonce });

// DeviceId reads verdict.device.ueid. Fail closed if it is missing: no id
// means you cannot prove the device is NOT banned.
if (result.DeviceId is null || await banList.Contains(result.DeviceId))
    return Results.Forbid();
```

## Targets

- .NET 8 (LTS)
- .NET 9

## License

MIT. See [LICENSE](./LICENSE).
