using System.Text.Json;
using System.Text.Json.Serialization;

namespace RootHerald.AspNetCore;

/// <summary>
/// Strongly-typed view of the device-attestation claims inside a verified
/// Root Herald JWT. Constructed by the JwtBearer events handler after the
/// signature, issuer, audience, and lifetime checks pass; available via
/// <c>HttpContext.GetRootHeraldVerdict()</c>.
/// </summary>
public sealed record RootHeraldVerdict
{
    /// <summary>Issuer URL the token was signed by.</summary>
    public required string Issuer { get; init; }

    /// <summary>Stable user ID (UUID) — the <c>sub</c> claim.</summary>
    public required string UserId { get; init; }

    /// <summary>Audience (your <c>client_id</c>) the token was issued to.</summary>
    public required string Audience { get; init; }

    /// <summary>
    /// The ACR URN that was satisfied (e.g. <c>urn:rootherald:device:high</c>,
    /// <c>urn:rootherald:user:phrh:fresh</c>).
    /// </summary>
    public required string Acr { get; init; }

    /// <summary>
    /// RFC 8176 authentication methods used. Empty array for device-only tiers.
    /// </summary>
    public required IReadOnlyList<string> Amr { get; init; }

    /// <summary>UTC instant when user authentication completed.</summary>
    public required DateTimeOffset AuthTime { get; init; }

    /// <summary>UTC instant when the token expires.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>The device attestation half of the verdict. Always present.</summary>
    public required RootHeraldDeviceVerdict Device { get; init; }
}

/// <summary>
/// Device attestation claims extracted from the <c>rootherald_device</c>
/// nested claim. The JWT carries this as a JSON-encoded string per
/// ADR-0012; this type is the parsed result.
///
/// JSON property mappings follow the wire-protocol contract in
/// docs/architecture/contracts/attestation-claims.md, not C# convention.
/// </summary>
public sealed record RootHeraldDeviceVerdict
{
    /// <summary>
    /// Stable per-tenant device identifier (UUID). Wire field: <c>ueid</c>
    /// (Universal Entity ID, RFC 9711 §4.2.1). Use this for ban lists,
    /// account binding, free-tier-per-device enforcement, etc.
    /// </summary>
    [JsonPropertyName("ueid")]
    public required string DeviceId { get; init; }

    /// <summary>Overall verdict: <c>"pass"</c>, <c>"warn"</c>, or <c>"fail"</c>.</summary>
    [JsonPropertyName("verdict")]
    public required string Verdict { get; init; }

    /// <summary>
    /// EAR status: <c>"affirming"</c>, <c>"warning"</c>, or <c>"contraindicated"</c>.
    /// </summary>
    [JsonPropertyName("ear_status")]
    public required string EarStatus { get; init; }

    /// <summary>
    /// Attestation mechanism that produced the evidence: <c>"tpm20"</c>,
    /// <c>"apple-se"</c>, <c>"android-ka"</c>, or <c>"ios-appattest"</c>.
    /// </summary>
    [JsonPropertyName("attestation_type")]
    public required string AttestationType { get; init; }

    /// <summary>UTC instant when the device evidence was submitted.</summary>
    [JsonPropertyName("attested_at")]
    [JsonConverter(typeof(UnixSecondsConverter))]
    public required DateTimeOffset AttestedAt { get; init; }

    /// <summary>
    /// Root-of-trust classification — kebab-cased, e.g.
    /// <c>"hardware-discrete-infineon"</c>, <c>"firmware-tpm-amd-ftpm"</c>,
    /// <c>"cloud-vtpm-aws-nitro"</c>, <c>"mobile-android-strongbox"</c>.
    /// </summary>
    [JsonPropertyName("tpm_class")]
    public string? TpmClass { get; init; }

    /// <summary>Client platform: <c>"windows"</c>, <c>"linux"</c>, <c>"macos"</c>, <c>"android"</c>, <c>"ios"</c>.</summary>
    [JsonPropertyName("platform")]
    public string? Platform { get; init; }

    /// <summary>
    /// Policy applied at verification time. Either a UUID (customer policy)
    /// or a stable built-in name (e.g. <c>"rootherald:builtin:strict-hardware"</c>).
    /// </summary>
    [JsonPropertyName("policy_id")]
    public string? PolicyId { get; init; }

    /// <summary>Version of the applied policy.</summary>
    [JsonPropertyName("policy_version")]
    public int? PolicyVersion { get; init; }

    /// <summary>True if the server verified a TPM quote signature.</summary>
    [JsonPropertyName("quote_verified")]
    public bool? QuoteVerified { get; init; }

    /// <summary>True if secure boot state was verified.</summary>
    [JsonPropertyName("secure_boot_verified")]
    public bool? SecureBootVerified { get; init; }

    /// <summary>True if the server replayed the event log and it matched.</summary>
    [JsonPropertyName("event_log_verified")]
    public bool? EventLogVerified { get; init; }

    internal static RootHeraldDeviceVerdict? FromClaim(string? claimValue)
    {
        if (string.IsNullOrWhiteSpace(claimValue)) return null;
        try
        {
            return JsonSerializer.Deserialize<RootHeraldDeviceVerdict>(claimValue);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

/// <summary>
/// Reads <c>attested_at</c> from unix seconds (number) and converts to
/// <see cref="DateTimeOffset"/>. The wire format is integer seconds; ASP.NET
/// JWT decoders surface it as a number, so a string fallback is also accepted.
/// </summary>
internal sealed class UnixSecondsConverter : JsonConverter<DateTimeOffset>
{
    public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert,
        JsonSerializerOptions options)
    {
        long seconds = reader.TokenType switch
        {
            JsonTokenType.Number => reader.GetInt64(),
            JsonTokenType.String when long.TryParse(reader.GetString(), out var s) => s,
            _ => 0,
        };
        return DateTimeOffset.FromUnixTimeSeconds(seconds);
    }

    public override void Write(Utf8JsonWriter writer, DateTimeOffset value,
        JsonSerializerOptions options) =>
        writer.WriteNumberValue(value.ToUnixTimeSeconds());
}
