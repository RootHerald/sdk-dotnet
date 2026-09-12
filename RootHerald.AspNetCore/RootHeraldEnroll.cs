using System.Text.Json.Serialization;

namespace RootHerald.AspNetCore;

/// <summary>
/// Enroll handshake — leg 1 request body, the output of the dumb client's
/// <c>EnrollBegin()</c> and the body of <c>POST /api/v1/attest/enroll</c>,
/// discriminated by <see cref="Platform"/>.
/// <para>
/// The client holds NO Root Herald key and opens NO socket to Root Herald — it
/// does local TPM work and hands these opaque blobs to your backend, which
/// relays them with its <c>rh_sk_</c> secret via
/// <see cref="RootHeraldClient.RelayEnrollAsync"/>. Field names are the
/// canonical wire keys the native client emits and the server binds.
/// </para>
/// <para>
/// <c>"windows"</c> / <c>"linux"</c> carry <see cref="EkPublicKey"/> and
/// <see cref="AkPublicArea"/>; <c>"macos"</c> carries the same enclave key in
/// both. <c>"ios"</c> carries <see cref="IosKeyId"/>,
/// <see cref="IosAttestationObject"/> and <see cref="Nonce"/> instead.
/// </para>
/// </summary>
public sealed record EnrollRequestBlob
{
    /// <summary>
    /// Reporting platform: <c>"windows"</c>, <c>"linux"</c>, <c>"macos"</c> or
    /// <c>"ios"</c>. Recorded on the device; activation demands the proof of the
    /// recorded platform, not of the request.
    /// </summary>
    [JsonPropertyName("platform")]
    public required string Platform { get; init; }

    /// <summary>
    /// base64 platform-native EK public blob (Windows: NCrypt <c>PCP_EKPUB</c>);
    /// on macOS the enclave key, X9.63 uncompressed. Required except on iOS.
    /// </summary>
    [JsonPropertyName("ekPublicKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? EkPublicKey { get; init; }

    /// <summary>
    /// base64 <c>TPM2B_PUBLIC</c> of the freshly created AK — the server hashes
    /// it into the AK Name used by <c>TPM2_MakeCredential</c> and later finds
    /// the device by the quote's signer. On macOS the same key as
    /// <see cref="EkPublicKey"/>. Required except on iOS.
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
    /// base64 ECDSA-P256-SHA256 signature over <c>challengeNonce</c>, DER or
    /// IEEE-P1363. macOS.
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
/// one. It goes to the backend and must never be relayed to the device.
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
/// (<see cref="RootHeraldClient.RelayEnrollAsync"/>).
/// <para>
/// Enrollment always issues a challenge, including for a device already known —
/// re-enrollment is how a device rotates its attestation key, so short-circuiting
/// it would make rotation impossible. Relay <see cref="Challenge"/> to the
/// client's <c>EnrollComplete</c>, then call
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
