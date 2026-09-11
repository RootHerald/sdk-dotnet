# Changelog

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
