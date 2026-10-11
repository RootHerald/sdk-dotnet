using System.Text.Json;
using System.Text.Json.Serialization;

namespace RootHerald.AspNetCore;

/// <summary>
/// Enroll handshake — leg 1 request body, the output of the client's
/// <c>EnrollBegin()</c> and the body of <c>POST /api/v1/attest/enroll</c>,
/// discriminated by <see cref="Platform"/>.
/// <para>
/// The client holds NO Root Herald key and opens NO socket to Root Herald — it
/// does local TPM work and hands these opaque blobs to your backend, which
/// relays them with its <c>rh_sk_</c> secret via
/// <see cref="RootHeraldClient.RelayEnrollAsync(EnrollRequestBlob, CancellationToken)"/>.
/// Field names are the canonical wire keys the native client emits and the
/// server binds; fields this type does not model are kept in
/// <see cref="ExtensionData"/> and relayed with the rest.
/// </para>
/// <para>
/// <c>"windows"</c> / <c>"linux"</c> carry <see cref="EkPublicKey"/> and the
/// nested <see cref="AttestationKey"/>; <c>"macos"</c> carries the same
/// enclave key in <see cref="EkPublicKey"/> and <see cref="AkPublicArea"/>;
/// <c>"ios"</c> carries <see cref="IosKeyId"/>,
/// <see cref="IosAttestationObject"/> and <see cref="Nonce"/> instead.
/// </para>
/// </summary>
public sealed record EnrollRequestBlob
{
    /// <summary>
    /// Reporting platform: <c>"windows"</c>, <c>"linux"</c>, <c>"macos"</c> or
    /// <c>"ios"</c>. Recorded on the installation; activation demands the proof
    /// of the recorded platform, not of the request.
    /// </summary>
    [JsonPropertyName("platform")]
    public required string Platform { get; init; }

    /// <summary>
    /// base64 <c>TPM2B_PUBLIC</c> of the endorsement key; on macOS the enclave
    /// key, X9.63 uncompressed. Required except on iOS.
    /// </summary>
    [JsonPropertyName("ekPublicKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? EkPublicKey { get; init; }

    /// <summary>
    /// This installation's attestation key and its storage parent. Required on
    /// <c>"windows"</c> and <c>"linux"</c>; absent on every other platform. The
    /// nested object is what tells an 8.0 body from a 7.0 one, which the server
    /// refuses with <c>400 wire_version_unsupported</c>.
    /// </summary>
    [JsonPropertyName("attestationKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AttestationKeyPublic? AttestationKey { get; init; }

    /// <summary>
    /// macOS only: the same enclave key as <see cref="EkPublicKey"/>. There is
    /// no parent, so the body stays flat. A TPM body carrying this field is the
    /// 7.0 shape and is refused locally.
    /// </summary>
    [JsonPropertyName("akPublicArea")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AkPublicArea { get; init; }

    /// <summary>
    /// PEM-encoded EK certificate. Optional: firmware TPMs (e.g. Intel PTT) ship
    /// no NV-stored EK cert; the server then fetches the vendor certificate itself.
    /// </summary>
    [JsonPropertyName("ekCertPem")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? EkCertPem { get; init; }

    /// <summary>
    /// PEM-encoded intermediate CA certs the client recovered from local sources
    /// (TPM NV, OS cert stores). Optional.
    /// </summary>
    [JsonPropertyName("ekCertificateChain")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? EkCertificateChain { get; init; }

    /// <summary>
    /// The TPM's own, unsigned answer to <c>TPM2_GetCapability</c>. The server
    /// reads it only downward — to recognise a software TPM that presents no EK
    /// certificate — never to promote a device. Optional.
    /// </summary>
    [JsonPropertyName("tpmSelfReport")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public TpmSelfReport? TpmSelfReport { get; init; }

    /// <summary>base64 App Attest key id. iOS only; required there.</summary>
    [JsonPropertyName("iosKeyId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IosKeyId { get; init; }

    /// <summary>base64 CBOR App Attest attestation object. iOS only; required there.</summary>
    [JsonPropertyName("iosAttestationObject")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IosAttestationObject { get; init; }

    /// <summary>
    /// The challenge handle the attestation was made over: the second segment
    /// of the <c>rhc1.</c> challenge string, verbatim (base64url, unpadded).
    /// The server finds the challenge by it and spends it. iOS only; required there.
    /// </summary>
    [JsonPropertyName("nonce")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Nonce { get; init; }

    /// <summary>
    /// Every field of the client's body this type does not name, so a body
    /// deserialized from the device is relayed whole.
    /// </summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; init; }
}

/// <summary>
/// The per-installation attestation key, as <c>EnrollBegin()</c> describes it
/// to the server. All three fields base64.
/// <para>
/// The server recomputes the qualified name from the two public areas and
/// refuses the enrollment (<c>400 invalid_enroll_shape</c>) when it differs
/// from <see cref="QualifiedName"/>, so a key created under the wrong parent
/// fails before any elevation prompt and before any row is written.
/// </para>
/// </summary>
public sealed record AttestationKeyPublic
{
    /// <summary><c>TPM2B_PUBLIC</c> of the AK, as <c>TPM2_Create</c> emitted it.</summary>
    [JsonPropertyName("publicArea")]
    public required string PublicArea { get; init; }

    /// <summary><c>TPM2B_PUBLIC</c> of the storage parent the AK was created under.</summary>
    [JsonPropertyName("parentPublicArea")]
    public required string ParentPublicArea { get; init; }

    /// <summary><c>TPM2B_NAME</c> qualified name of the AK, as <c>TPM2_ReadPublic</c> returned it.</summary>
    [JsonPropertyName("qualifiedName")]
    public required string QualifiedName { get; init; }

    /// <summary>Every field of the client's object this type does not name, relayed with the rest.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; init; }
}

/// <summary>The TPM's unsigned self-description on an enroll request.</summary>
public sealed record TpmSelfReport
{
    /// <summary>The <c>TPM_PT_MANUFACTURER</c> vendor id, e.g. <c>"INTC"</c>.</summary>
    [JsonPropertyName("manufacturer")]
    public required string Manufacturer { get; init; }

    /// <summary>The concatenated <c>TPM_PT_VENDOR_STRING_*</c> properties.</summary>
    [JsonPropertyName("vendorString")]
    public required string VendorString { get; init; }

    /// <summary>Every field of the client's object this type does not name, relayed with the rest.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; init; }
}

/// <summary>
/// The activation challenge — the <c>201</c> response body of
/// <c>POST /api/v1/attest/enroll</c> and the input to the client's
/// <c>EnrollComplete()</c>, relayed verbatim.
/// <para>
/// TPM: <see cref="CredentialBlob"/> and <see cref="EncryptedSecret"/> are the
/// <c>TPM2_MakeCredential</c> outputs the client feeds straight into
/// <c>TPM2_ActivateCredential</c>. macOS: <see cref="ChallengeNonce"/> is the
/// nonce the enclave key signs.
/// </para>
/// </summary>
public sealed record EnrollActivationChallenge
{
    /// <summary>
    /// The server's handle for this open enrollment (UUID). Echoed back in the
    /// <see cref="EnrollActivationResponse"/>; spent by activation.
    /// </summary>
    [JsonPropertyName("enrollmentId")]
    public required string EnrollmentId { get; init; }

    /// <summary>base64 <c>TPM2_MakeCredential</c> credential blob (<c>id-object</c>). Windows/Linux.</summary>
    [JsonPropertyName("credentialBlob")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CredentialBlob { get; init; }

    /// <summary>base64 <c>TPM2_MakeCredential</c> encrypted secret (<c>encrypted-secret</c>). Windows/Linux.</summary>
    [JsonPropertyName("encryptedSecret")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? EncryptedSecret { get; init; }

    /// <summary>base64 nonce for the enclave key to sign. macOS.</summary>
    [JsonPropertyName("challengeNonce")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ChallengeNonce { get; init; }
}

/// <summary>
/// Enroll handshake — leg 2 request body, the output of the client's
/// <c>EnrollComplete()</c> and the body of <c>POST /api/v1/attest/activate</c>.
/// The proof is per platform: a TPM returns the secret it released inside
/// <c>TPM2_ActivateCredential</c>; a Secure Enclave returns a signature over
/// <see cref="EnrollActivationChallenge.ChallengeNonce"/>.
/// </summary>
public sealed record EnrollActivationResponse
{
    /// <summary>The <c>enrollmentId</c> from the <see cref="EnrollActivationChallenge"/>. Required.</summary>
    [JsonPropertyName("enrollmentId")]
    public required string EnrollmentId { get; init; }

    /// <summary>
    /// base64 of the 32-byte secret released by <c>TPM2_ActivateCredential</c> —
    /// proof the AK is bound to the attested EK. Windows/Linux.
    /// </summary>
    [JsonPropertyName("decryptedSecret")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DecryptedSecret { get; init; }

    /// <summary>
    /// base64 ECDSA-P256-SHA256 signature over the fixed prefix and
    /// <c>challengeNonce</c>, DER or IEEE-P1363. macOS.
    /// </summary>
    [JsonPropertyName("signature")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Signature { get; init; }
}

/// <summary>
/// Terminal response of the activate relay leg — <c>POST /api/v1/attest/activate</c>.
/// Mirrors the server's <c>{ deviceId, status, enrolledAt }</c> body;
/// <see cref="DeviceId"/> is the load-bearing field the backend maps to its user.
/// <para>
/// <see cref="DeviceId"/> is THIS tenant's alias for the device, not a global
/// identifier: another tenant enrolling the same silicon is told a different
/// one. It goes to the backend and must never be relayed to the device. A new
/// attestation key, a re-enrollment or a TPM clear never changes it.
/// </para>
/// </summary>
public sealed record RelayActivateResponse
{
    /// <summary>This tenant's alias for the enrolled device (UUID).</summary>
    [JsonPropertyName("deviceId")]
    public required string DeviceId { get; init; }

    /// <summary>Lifecycle status, e.g. <c>"enrolled"</c>. Optional.</summary>
    [JsonPropertyName("status")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Status { get; init; }

    /// <summary>ISO 8601 timestamp the device was enrolled. Optional.</summary>
    [JsonPropertyName("enrolledAt")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? EnrolledAt { get; init; }
}

/// <summary>
/// Result of the enroll relay leg
/// (<see cref="RootHeraldClient.RelayEnrollAsync(EnrollRequestBlob, CancellationToken)"/>).
/// <para>
/// Enrollment always issues a challenge, including for a device already known:
/// each activation creates a new installation of the device with its own
/// attestation key. Relay <see cref="Challenge"/> to the client's
/// <c>EnrollComplete</c>, then call
/// <see cref="RootHeraldClient.RelayActivateAsync"/>. The backend learns the
/// device's alias from <see cref="RelayActivateResponse.DeviceId"/>, not here.
/// </para>
/// </summary>
public sealed record RelayEnrollResult
{
    /// <summary>
    /// The 201 body to hand to the client's <c>EnrollComplete</c>. Null for an
    /// iOS enrollment: the attestation object carries the whole proof, the
    /// server answers <c>{}</c>, and there is nothing to activate.
    /// </summary>
    public required EnrollActivationChallenge? Challenge { get; init; }
}
