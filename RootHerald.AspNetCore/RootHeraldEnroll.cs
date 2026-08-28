using System.Text.Json.Serialization;

namespace RootHerald.AspNetCore;

/// <summary>
/// Client ABI 3.0 enroll handshake — leg 1 request body, the output of the dumb
/// client's <c>EnrollBegin()</c> and the body of
/// <c>POST /api/v1/devices/enroll</c>.
/// <para>
/// The client holds NO Root Herald key and opens NO socket to Root Herald — it
/// does local TPM work and hands these opaque blobs to your backend, which
/// relays them with its <c>rh_sk_</c> secret via
/// <see cref="RootHeraldClient.RelayEnrollAsync"/>. Field names
/// are the canonical wire keys the native client emits and the server binds.
/// </para>
/// </summary>
public sealed record EnrollRequestBlob
{
    /// <summary>
    /// base64 platform-native EK public blob (Windows: NCrypt <c>PCP_EKPUB</c>) —
    /// the stable hardware anchor the deterministic <c>deviceId</c> is derived
    /// from. Required.
    /// </summary>
    [JsonPropertyName("ekPublicKey")]
    public required string EkPublicKey { get; init; }

    /// <summary>
    /// base64 <c>TPM2B_PUBLIC</c> of the freshly created AK — the server hashes
    /// it into the AK Name used by <c>TPM2_MakeCredential</c>. Required.
    /// </summary>
    [JsonPropertyName("akPublicArea")]
    public required string AkPublicArea { get; init; }

    /// <summary>
    /// Reporting platform: <c>"windows"</c>, <c>"linux"</c>, or <c>"macos"</c>
    /// for the desktop TPM enroll path.
    /// </summary>
    [JsonPropertyName("platform")]
    public required string Platform { get; init; }

    /// <summary>
    /// PEM-encoded EK certificate. Optional: firmware TPMs (e.g. Intel PTT) ship
    /// no NV-stored EK cert and the manufacturer AIA fallback may be unavailable.
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
}

/// <summary>
/// The MakeCredential challenge — the <c>201</c> response body of
/// <c>POST /api/v1/devices/enroll</c> and the input to the client's
/// <c>EnrollComplete()</c>. <see cref="CredentialBlob"/> and
/// <see cref="EncryptedSecret"/> are the <c>TPM2_MakeCredential</c> outputs the
/// client feeds straight into <c>TPM2_ActivateCredential</c>.
/// </summary>
public sealed record EnrollActivationChallenge
{
    /// <summary>The deterministic device id (UUID), derived server-side from the EK.</summary>
    [JsonPropertyName("deviceId")]
    public required string DeviceId { get; init; }

    /// <summary>base64 <c>TPM2_MakeCredential</c> credential blob (<c>id-object</c>).</summary>
    [JsonPropertyName("credentialBlob")]
    public required string CredentialBlob { get; init; }

    /// <summary>base64 <c>TPM2_MakeCredential</c> encrypted secret (<c>encrypted-secret</c>).</summary>
    [JsonPropertyName("encryptedSecret")]
    public required string EncryptedSecret { get; init; }
}

/// <summary>
/// Client ABI 3.0 enroll handshake — leg 2 request body, the output of the
/// client's <c>EnrollComplete()</c> and the body of
/// <c>POST /api/v1/devices/activate</c>. The client decrypts the challenge inside
/// the TPM and returns the released secret to prove the EK→AK binding.
/// </summary>
public sealed record EnrollActivationResponse
{
    /// <summary>The <c>deviceId</c> from the <see cref="EnrollActivationChallenge"/>. Required.</summary>
    [JsonPropertyName("deviceId")]
    public required string DeviceId { get; init; }

    /// <summary>
    /// base64 of the secret released by <c>TPM2_ActivateCredential</c> — proof the
    /// AK is bound to the attested EK. Required.
    /// </summary>
    [JsonPropertyName("decryptedSecret")]
    public required string DecryptedSecret { get; init; }

    /// <summary>
    /// Optional base64 AK public area re-sent for the server's anti
    /// key-substitution check. The current Windows client omits it; the server
    /// validates it against the credential-activated AK when present.
    /// </summary>
    [JsonPropertyName("akPublicKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AkPublicKey { get; init; }
}

/// <summary>
/// Terminal response of the activate relay leg — <c>POST /api/v1/devices/activate</c>.
/// Mirrors the server's <c>{ deviceId, status, enrolledAt }</c> body;
/// <see cref="DeviceId"/> is the load-bearing field the backend maps to its user.
/// </summary>
public sealed record RelayActivateResponse
{
    /// <summary>The enrolled device id (UUID).</summary>
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
/// (<see cref="RootHeraldClient.RelayEnrollAsync"/>).
/// <para>
/// Enrolment always issues a challenge, including for a device already known —
/// re-enrolment is how a device rotates its attestation key, so short-circuiting
/// it would make rotation impossible. Relay <see cref="Challenge"/> to the
/// client's <c>EnrollComplete</c>, then call
/// <see cref="RootHeraldClient.RelayActivateAsync"/>.
/// </para>
/// <para>
/// <see cref="DeviceId"/> is THIS tenant's alias for the device, not a global
/// identifier: another tenant enrolling the same silicon is told a different one.
/// </para>
/// </summary>
public sealed record RelayEnrollResult
{
    /// <summary>This tenant's alias for the device.</summary>
    public required string DeviceId { get; init; }

    /// <summary>
    /// The MakeCredential challenge to hand to the client's <c>EnrollComplete</c>.
    /// </summary>
    public required EnrollActivationChallenge Challenge { get; init; }
}
