# Changelog

## 0.1.0-preview.5

Wire 8.0. Every installation of a client has its own attestation key, created
inside the TPM at enrollment and handed back as an opaque AK blob the client
keeps and passes to every attest and mint. Keys are minted in their own
ceremony. A backend on this version cannot drive a 7.0 client, and the
reverse; the server refuses a 7.0-shaped enroll body with
`400 wire_version_unsupported`.

Breaking.

- `RelayEnrollAsync` takes the 8.0 TPM body: `EnrollRequestBlob.AttestationKey`
  (`AttestationKeyPublic { PublicArea, ParentPublicArea, QualifiedName }`)
  replaces the top-level `AkPublicArea` on `windows` / `linux`, and a flat TPM
  body is refused locally with `ArgumentException`. `AkPublicArea` stays for
  `macos`; the iOS body is unchanged. A new `RelayEnrollAsync(JsonObject)`
  overload relays the client's JSON as-is, and the typed records keep fields
  they do not model (`ExtensionData`), so every body is relayed whole.
- Keys are minted by `IssueKeyChallengeAsync(new KeyChallengeOptions {
  Purpose, ExpectedDevices? })` → `RootHeraldKeyChallenge` →
  `CertifyKeyAsync(nonce, certification)` → `CertifiedKey { DeviceId, KeyId,
  Purpose, Alg, Format?, Jwk, HardwareBound, CertifiedAt }`. `Ask.Key`,
  `ChallengeOptions.KeyPurpose` and `AttestResult.Key` are removed, and
  `CertifiedKey.AuthPolicy` with them; a challenge that still asks for
  `"key"` is `InvalidAskException` (400 `invalid_ask`), not
  `InvalidEvidenceException`.
- `IssueChallengeAsync` takes `ChallengeOptions.ExpectedKey` and
  `ExpectedDevices` and no longer takes `DeviceHint`; the
  `IssueChallengeAsync(string? deviceHint)` overload is gone. Pass the same
  values in `AttestOptions`: a verdict that does not echo them under
  `verdict.expected` (`AttestResult.Expected`) is refused with
  `ExpectedNotEnforcedException`.
- `CertifiedKey.Jwk` is EC P-256 or RSA-2048; `VerifyKeySignature` checks
  ES256 (raw `r||s` or DER) and RS256 (PKCS#1 v1.5 over SHA-256, modulus at
  least 2048 bits). P-384 is no longer accepted: no client certifies one.
- A 429 `budget_exhausted` is `QuotaExceededException` with `Budget { Id,
  Name }`; the `quota_exceeded` code is gone. A 409 `key_rotation_conflict` is
  a plain `RootHeraldApiException`, not `ChallengeException`. A 400
  `wire_version_unsupported` or `invalid_enroll_shape` is
  `InvalidEvidenceException`; a 422 `expected_unknown` or
  `key_disclosure_too_low` is a plain `RootHeraldApiException`.
- Carried over from the unreleased changes after `0.1.0-preview.4`:
  `AttestResult.Verdict` is the server's own token, `Verdict.Pass` /
  `Verdict.Warn` / `Verdict.Fail`, and `IsAllowed` is `IsPass`; a 401
  `activation_refused` is `ActivationRefusedException`; a 429 without a
  budget signal is `RateLimitedException` with `RetryAfterSeconds`; a 422
  whose code no subclass covers is a plain `RootHeraldApiException`; the
  `HttpClient` the constructor creates times out after 30 s.

Migration.

1. Re-enroll every installation: the client's `EnrollBegin` now returns an
   AK blob, which the client keeps and passes to `Attest` and `MintKey`.
2. Replace `IssueChallengeAsync(new ChallengeOptions { Ask = [Identity, Key],
   KeyPurpose = "sign" })` plus `result.Key` with
   `IssueKeyChallengeAsync(new KeyChallengeOptions { Purpose = KeyPurpose.Sign,
   ExpectedDevices = [alias] })` and `CertifyKeyAsync(nonce, certification)`.
3. Drop `DeviceHint`; bind a challenge to a device with `ExpectedDevices`,
   and pass the same list to `VerifyAsync`.
4. Build TPM enroll bodies with `AttestationKey`, or relay the client's JSON
   through `RelayEnrollAsync(JsonObject)`.
5. Catch `InvalidAskException` where a wrong ask was previously
   `InvalidEvidenceException`, and read `QuotaExceededException.Budget`.

## 0.1.0-preview.4

Breaking. Nothing the backend sends locates a row by an id the server
assigned; the server resolves the challenge from the nonce the proof was made
over, the enrollment from the `enrollmentId` it minted, and the device from
the proof itself.

- `RootHeraldChallenge` is `(Nonce, Challenge, ExpiresAt)`; `ChallengeId` is
  gone and `Challenge` is always present. `Nonce` is the handle:
  `AttestOptions.Nonce` replaces `AttestOptions.ChallengeId` and goes on the
  wire as `nonce`.
- `RelayEnrollAsync(blob)` takes no challenge id and sends no query string.
  `RelayEnrollResult` is `{ Challenge }`; `DeviceId` is gone. The 201 is
  validated as `enrollmentId` plus `credentialBlob` + `encryptedSecret` (TPM)
  or `challengeNonce` (macOS); an iOS blob gets `{}` and a null `Challenge`.
- `EnrollRequestBlob` is discriminated by `Platform`: `EkPublicKey` and
  `AkPublicArea` are optional on the type and required for `windows`, `linux`
  and `macos`; `IosKeyId`, `IosAttestationObject` and `Nonce` are required for
  `ios`. `TpmSelfReport` (`Manufacturer`, `VendorString`) is carried when set.
- `EnrollActivationChallenge` is `{ EnrollmentId, CredentialBlob?,
  EncryptedSecret?, ChallengeNonce? }`; `DeviceId` and `ChallengeId` are gone.
  `EnrollActivationResponse` is `{ EnrollmentId, DecryptedSecret?, Signature? }`;
  `DeviceId` and `AkPublicKey` are gone. `RelayActivateAsync` requires
  `EnrollmentId` and one of `DecryptedSecret` / `Signature`.
- `RelayActivateResponse.DeviceId` is unchanged and is where the backend
  learns its alias for the device; it must never be relayed to the device.

## 0.1.0-preview.3

Breaking. Policies bind to API keys, not to calls.

- The `Policy` property is gone from `ChallengeOptions` and `AttestOptions`.
  The server resolves the policy from the key that mints the challenge and
  pins it there; a `policy` field in a hand-built body is refused with
  `400 policy_bound_to_key`. Bind a policy to the key from the dashboard or
  `PUT /api/v1/admin/api-keys/{id}/policies`.
- `PolicyDowngradeException` is removed with the property that produced it.
  `UnknownPolicyException` (422 `unknown_policy`) now means a policy bound to
  the key no longer exists; nothing is substituted.
- `RelayEnrollAsync(blob, challengeId)` keeps its shape. Admission runs under
  the identity policy bound to the key, pinned on the challenge when one is
  given.

## 0.1.0-preview.2

Additive. Existing calls keep their shape and behaviour.

- The challenge carries the ask. `IssueChallengeAsync(ChallengeOptions?)`
  takes `Ask` (from the `Ask` constants: `Identity`, `Posture`, `Key`),
  `Policy`, `KeyPurpose` and `DeviceHint`; the `(string? deviceHint)` overload
  forwards to it and still sends no ask, which the server reads as
  identity + posture. `RootHeraldChallenge` gains `Challenge`, the `rhc1.`
  string to relay to the client verbatim; `Nonce` stays.
- `AttestResult.Key` (`CertifiedKey`: `KeyId`, `Jwk`, `Purpose`,
  `AuthPolicy`, `CertifiedAt`) is the signing key a passing verdict certified
  when the challenge asked for `Ask.Key`; null otherwise.
  `AttestResult.DeviceId` reads `verdict.device.ueid`.
- `RootHeraldClient.VerifyKeySignature(jwk, message, signature)` checks a
  device's signature locally, ECDSA over SHA-256/SHA-384 for P-256/P-384, raw
  `r||s` or DER. Returns false for anything it cannot verify; never throws.
- `RelayEnrollAsync(blob, challengeId)` admits against the challenge's policy
  (`?challengeId=` on the enroll request). `EnrollActivationChallenge` gains
  `ChallengeId`. Callers passing a `CancellationToken` positionally as the
  second argument now name it.
- `PolicyDowngradeException` (422 `policy_downgrade`) and
  `AdmissionRefusedException` (422 `admission_refused`), told apart from
  `UnknownPolicyException` by the server's error code, which every
  `RootHeraldApiException` exposes as `ErrorCode`. The refused TPM class is in
  the message.
- READMEs rewritten to the real API: the package README named a
  `RootHeraldBackgroundCheckClient` type that does not exist, and the
  top-level README described a `409` short-circuit the server never sends.

## 0.1.0-preview.1

Initial preview.
