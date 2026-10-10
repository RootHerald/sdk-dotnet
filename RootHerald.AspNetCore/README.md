# RootHerald.AspNetCore

Server-side .NET SDK for Root Herald device attestation. Pure managed C#, with
no native dependencies and no DLL bundling, so single-file publish works without
extra steps.

Wire 8.0 from `0.1.0-preview.5`. A 7.0 client cannot enroll against an 8.0
server; see the [CHANGELOG](../CHANGELOG.md) for the migration.

**Backend relay (server → server).** The user's client does local TPM work and
hands your server opaque blobs (no keys, no Root Herald contact). Your server
relays those blobs to Root Herald with `RootHeraldClient`, authenticated by
your `rh_sk_` secret key. The verdict is computed by Root Herald and returned
to your backend; it never travels through the client.

**Three ceremonies, two calls each.**

- `RelayEnrollAsync(enrollRequestBlob)` / `RelayActivateAsync(activationResponse)`:
  enroll an installation (`POST /api/v1/attest/enroll`, `/activate`).
- `IssueKeyChallengeAsync(new KeyChallengeOptions { Purpose, ExpectedDevices? })` /
  `CertifyKeyAsync(nonce, certification)`: mint a device-bound key
  (`POST /api/v1/keys/challenge`, `/certify`).
- `IssueChallengeAsync(new ChallengeOptions { Ask?, ExpectedKey?, ExpectedDevices? })` /
  `VerifyAsync(evidence, new AttestOptions { Nonce, RequestedDisclosureClass?, ExpectedKey?, ExpectedDevices? })`:
  attest (`POST /api/v1/attest/challenge`, `/verify`).
- `RootHeraldClient.VerifyKeySignature(jwk, message, signature)`: check a
  signature from a certified key locally, with `System.Security.Cryptography` only.

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

    return result.IsPass
        ? Results.Json(new { ok = true, verdict = result.Verdict })
        // An un-enrolled / failing device is a verdict, NOT an error.
        : Results.Json(new { ok = false, verdict = result.Verdict }, statusCode: 403);
});

app.Run();
```

`VerifyAsync` returns an `AttestResult` whose `Verdict` is the server's own
token, `Verdict.Pass` / `Verdict.Warn` / `Verdict.Fail` (`"pass"` / `"warn"` /
`"fail"`, the same vocabulary in every RootHerald SDK), with `IsPass` as a
convenience and `DeviceId` reading `verdict.device.ueid`. A response carrying
any other token is refused with `RootHeraldApiException`, never a guessed
verdict. The full server verdict object is available verbatim as a `JsonNode`
on `VerdictData`; every field the server sends under `device` flows through,
and a field gated by disclosure class is absent below it. Protocol, auth and
budget problems raise a typed `RootHeraldApiException`; see [Errors](#errors).

## Enroll an installation

Each installation of your client enrolls once. The client's `EnrollBegin`
creates an attestation key (AK) inside the TPM and returns an opaque AK blob
alongside the enroll body; the client keeps the blob and passes it to every
later attest and mint. Windows needs one elevation per enrollment.

```csharp
// Leg 1: relay the client's EnrollBegin() body verbatim. Admission runs under
// the key's identity policy, so a device that could never satisfy it is
// refused before it gets an attestation key.
var enroll = await rh.RelayEnrollAsync(enrollRequestBlob); // POST /api/v1/attest/enroll

// Hand enroll.Challenge (the 201 body) to the client's EnrollComplete(), which
// returns an activationResponse; relay it to finish binding.
var activated = await rh.RelayActivateAsync(activationResponse); // POST /api/v1/attest/activate
// activated.DeviceId is this tenant's alias for the device. Keep it here; do
// not send it back to the client.
```

`RelayEnrollAsync` takes the body as an `EnrollRequestBlob` or as the
`JsonObject` your endpoint received; either way it is relayed whole, fields
this SDK does not model included. `EnrollRequestBlob.Platform` discriminates:
`"windows"` / `"linux"` carry `EkPublicKey` and the nested `AttestationKey`
(`PublicArea`, `ParentPublicArea`, `QualifiedName`); `"macos"` carries
`EkPublicKey` and `AkPublicArea`; `"ios"` carries `IosKeyId`,
`IosAttestationObject` and `Nonce`, the server answers `{}`, `enroll.Challenge`
is null and there is no activate leg. A TPM body with a top-level
`AkPublicArea` is the 7.0 shape and is refused locally with `ArgumentException`.

The alias is the device's only identity: a new AK, a new key, a re-enrollment
or a TPM clear never changes it. Bind accounts to it.

When to enroll:

- The client has no AK blob: enroll first.
- The client's attest or mint reports the AK blob unloadable (TPM cleared,
  parent changed): discard the blob, enroll, retry once.
- `VerifyAsync` answers `EnrollmentRequired = true`: enroll.

## Attest

```csharp
// 1. Mint a challenge. Relay challenge.Challenge to the client; keep Nonce.
var challenge = await rh.IssueChallengeAsync(new ChallengeOptions { Ask = new[] { Ask.Identity } });

// 2. The client's Attest answers with an opaque evidence blob. Appraise it.
var result = await rh.VerifyAsync(evidence, new AttestOptions { Nonce = challenge.Nonce });

if (result.IsPass)
{
    // result.DeviceId is the alias: bind the session to it.
}
```

Omitting `Ask` asks for identity and posture. A posture ask runs under the
key's posture policy and checks the boot configuration; use it for step-up,
with `result.AssuranceClaimsMet` listing the policy claims the device satisfied.

**Name the device that must answer.** `ExpectedDevices` takes aliases you
enrolled, `ExpectedKey` a `KeyId` you certified; any other device answers a
failing verdict with reason `expected_device_mismatch`, and an unknown value
is `422 expected_unknown`. Pass the same values to `VerifyAsync`: the verdict
echoes what the server enforced under `verdict.expected` (`result.Expected`),
and `VerifyAsync` refuses a verdict that does not echo it with
`ExpectedNotEnforcedException`.

```csharp
var challenge = await rh.IssueChallengeAsync(new ChallengeOptions
{
    Ask = new[] { Ask.Identity },
    ExpectedDevices = new[] { session.DeviceId },
});
var result = await rh.VerifyAsync(evidence, new AttestOptions
{
    Nonce = challenge.Nonce,
    ExpectedDevices = new[] { session.DeviceId },
});
```

Policies bind to your API key, not to calls. The key carries an identity
policy and, on Pro, a posture policy; the resolved policy is pinned on the
challenge when it is minted. Change what a key enforces from the dashboard or
`PUT /api/v1/admin/api-keys/{id}/policies`; a `policy` field in a hand-built
request body is refused with `400 policy_bound_to_key`. `UnknownPolicyException`
(422 `unknown_policy`) means a policy bound to the key no longer exists;
nothing is substituted.

## Device-bound signing keys

A key is created inside the chip and certified by the installation's AK; you
get its public half, the device keeps the blob. A signature on a request then
proves the request came from that device, and you check it with no Root
Herald call.

```csharp
// 1. Mint a key challenge for the device that just passed an attest
//    challenge. Relay keyChallenge.KeyChallenge to the client; keep Nonce.
var keyChallenge = await rh.IssueKeyChallengeAsync(new KeyChallengeOptions
{
    Purpose = KeyPurpose.Sign,
    ExpectedDevices = new[] { result.DeviceId! },
});

// 2. The client's MintKey answers with a certification and keeps its key blob.
var key = await rh.CertifyKeyAsync(keyChallenge.Nonce, certification);
await store.SaveAsync(key.DeviceId, key.KeyId, key.Jwk);

// Later, without any Root Herald call: the client signed `message` with its
// key and sent { message, signature }.
var jwk = await store.LoadAsync(session.DeviceId);
if (!RootHeraldClient.VerifyKeySignature(jwk, message, signature))
    return Results.Forbid();
```

`CertifyKeyAsync` returns a `CertifiedKey`:

```csharp
key.DeviceId      // the alias of the device that holds the key
key.KeyId         // Root Herald's id for the key
key.Purpose       // KeyPurpose.Sign | KeyPurpose.Decrypt
key.Alg           // "ES256" | "RS256" | "ECDH-ES" | "RSA-OAEP-256"
key.Format        // "jwe" | "apple-ecies" | null — decrypt keys only
key.Jwk           // { kty: "EC", crv: "P-256", x, y } or { kty: "RSA", n, e }
key.HardwareBound // false on macOS, where only possession is proved
key.CertifiedAt   // DateTimeOffset
```

Keys are EC P-256 or RSA-2048, chosen by the device from what its TPM
supports. A signature proves which chip signed, not how the machine booted;
run an attest challenge for that.

Minting again for the same purpose rotates the key under the same `KeyId`; a
re-enrolled installation gets new key ids. The key id identifies an
installation's credential, never a device: bind accounts to the alias.

`VerifyKeySignature(jwk, message, signature)` takes the message and the
signature as bytes. ES256: a 64-byte signature is read as IEEE P1363
`r || s`, any other length as DER. RS256: PKCS#1 v1.5 over SHA-256, exactly the
modulus length (256 bytes). It returns false and never throws on malformed input.

## Errors

An un-enrolled or failing device is a verdict, not an exception. Only
protocol, auth and budget problems throw, each exposing the HTTP `StatusCode`
and the server's `ErrorCode`:

| Status | Server `error` code                                                      | Exception                       |
| ------ | ------------------------------------------------------------------------ | ------------------------------- |
| 401    | `activation_refused`                                                     | `ActivationRefusedException`    |
| 401    | anything else                                                            | `InvalidSecretKeyException`     |
| 400    | `invalid_ask`                                                            | `InvalidAskException`           |
| 400    | anything else, including `wire_version_unsupported`, `invalid_enroll_shape` | `InvalidEvidenceException`   |
| 409    | `key_rotation_conflict`                                                  | `RootHeraldApiException`        |
| 409    | anything else                                                            | `ChallengeException`            |
| 422    | `unknown_policy`, or none                                                | `UnknownPolicyException`        |
| 422    | `admission_refused`                                                      | `AdmissionRefusedException`     |
| 422    | `expected_unknown`, `key_disclosure_too_low`                             | `RootHeraldApiException`        |
| 429    | `budget_exhausted`, or an `X-RootHerald-Quota` header                    | `QuotaExceededException` (`Budget`) |
| 429    | anything else                                                            | `RateLimitedException`          |

`ActivationRefusedException` is `RelayActivateAsync` being refused for an
unknown, spent or foreign `EnrollmentId` or a wrong proof; the secret key was
accepted. `InvalidAskException` is a programming error in your backend, not a
device failure. `RateLimitedException.RetryAfterSeconds` is the server's
`Retry-After` (else the body's `retryAfterSeconds`, else null);
`QuotaExceededException.Budget` names the budget that refused. Any other
status, and a code no subclass covers (`posture_not_bound`, `plan_lapsed`), is
a plain `RootHeraldApiException` with `ErrorCode` preserved.

A response whose `verdict.device.verdict` is not `pass`/`warn`/`fail`, or
whose certified key is malformed, is refused with a `RootHeraldApiException`
of status 200 rather than returned half-parsed. A verdict that does not echo
the `ExpectedKey` / `ExpectedDevices` you passed to `VerifyAsync` is
`ExpectedNotEnforcedException`. Input the SDK refuses locally, such as an
empty `Nonce` or a 7.0-shaped enroll body, is `ArgumentException` and makes no
request.

Every request times out after 30 s (`RootHeraldClient.DefaultTimeout`) unless
you supply your own `HttpClient`, whose `Timeout` is then used as is. The
default is the same in every RootHerald server SDK.

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
