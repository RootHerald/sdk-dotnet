using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace RootHerald.AspNetCore;

/// <summary>
/// A challenge minted by <see cref="RootHeraldClient.IssueChallengeAsync"/>.
/// Relay <see cref="Challenge"/> to the client verbatim; it parses the
/// nonce and the ask from it, quotes over the nonce, and returns an opaque
/// evidence blob, which the server submits to
/// <see cref="RootHeraldClient.VerifyAsync"/> using <see cref="Nonce"/>.
/// </summary>
/// <param name="Nonce">
/// The backend's handle for this challenge: 32 random bytes, base64url without
/// padding. The same bytes as the second segment of <paramref name="Challenge"/>;
/// the server finds the challenge by it. Pass it to VerifyAsync.
/// </param>
/// <param name="Challenge">
/// The string to relay to the client: <c>rhc1.&lt;base64url nonce&gt;.&lt;base64url ask-json&gt;</c>.
/// </param>
/// <param name="ExpiresAt">ISO 8601 timestamp after which the challenge is no longer valid.</param>
public sealed record RootHeraldChallenge(string Nonce, string Challenge, string ExpiresAt);

/// <summary>
/// A key challenge minted by <see cref="RootHeraldClient.IssueKeyChallengeAsync"/>.
/// Relay <see cref="KeyChallenge"/> to the client verbatim; its <c>MintKey</c>
/// reads the nonce and the purpose from it, creates the key and has the
/// installation's attestation key certify it, and returns a certification,
/// which the server submits to <see cref="RootHeraldClient.CertifyKeyAsync"/>
/// using <see cref="Nonce"/>.
/// </summary>
/// <param name="Nonce">The backend's handle for this key challenge, as <see cref="RootHeraldChallenge.Nonce"/>.</param>
/// <param name="KeyChallenge">
/// The string to relay to the client: <c>rhk1c.&lt;base64url nonce&gt;.&lt;base64url purpose-json&gt;</c>.
/// </param>
/// <param name="ExpiresAt">ISO 8601 timestamp after which the key challenge is no longer valid.</param>
public sealed record RootHeraldKeyChallenge(string Nonce, string KeyChallenge, string ExpiresAt);

/// <summary>
/// What a challenge asks the device to prove. Keys are never asked for here;
/// they have their own ceremony (<see cref="RootHeraldClient.IssueKeyChallengeAsync"/>),
/// and a <c>"key"</c> ask is refused with <see cref="InvalidAskException"/>.
/// </summary>
public static class Ask
{
    /// <summary>This is a specific, enrolled installation: a quote under its attestation key.</summary>
    public const string Identity = "identity";

    /// <summary>The boot configuration: the measured-boot event log alongside the quote.</summary>
    public const string Posture = "posture";
}

/// <summary>
/// What a minted key is for. One live key per installation per purpose;
/// minting again rotates it under the same <c>keyId</c>.
/// </summary>
public static class KeyPurpose
{
    /// <summary>A signing key: ES256 or RS256, checked with <see cref="RootHeraldClient.VerifyKeySignature"/>.</summary>
    public const string Sign = "sign";

    /// <summary>A decryption key: ECDH-ES or RSA-OAEP-256. The server refuses the purpose before wire 8.1.</summary>
    public const string Decrypt = "decrypt";

    internal static readonly string[] All = [Sign, Decrypt];
}

/// <summary>
/// Options for <see cref="RootHeraldClient.IssueChallengeAsync"/>.
/// The default asks for identity and posture.
/// </summary>
public sealed record ChallengeOptions
{
    /// <summary>
    /// What the device must prove, from the <see cref="Ask"/> constants. Null
    /// or empty means identity + posture.
    /// </summary>
    public IReadOnlyList<string>? Ask { get; init; }

    /// <summary>
    /// The <c>KeyId</c> of a key you certified. Only the installation holding
    /// that key can pass; any other answers a failing verdict with reason
    /// <c>expected_device_mismatch</c>. An unknown id is <c>422 expected_unknown</c>.
    /// Pass the same value to <see cref="AttestOptions.ExpectedKey"/>.
    /// </summary>
    public string? ExpectedKey { get; init; }

    /// <summary>
    /// Aliases (<see cref="AttestResult.DeviceId"/>) you enrolled. Only one of
    /// them can pass; any other device answers a failing verdict with reason
    /// <c>expected_device_mismatch</c>. An unknown alias is <c>422 expected_unknown</c>.
    /// Pass the same list to <see cref="AttestOptions.ExpectedDevices"/>.
    /// </summary>
    public IReadOnlyList<string>? ExpectedDevices { get; init; }
}

/// <summary>Options for <see cref="RootHeraldClient.IssueKeyChallengeAsync"/>.</summary>
public sealed record KeyChallengeOptions
{
    /// <summary>What the key is for, from the <see cref="KeyPurpose"/> constants. Required.</summary>
    public required string Purpose { get; init; }

    /// <summary>
    /// Aliases (<see cref="AttestResult.DeviceId"/>) you enrolled. The certify
    /// leg is refused unless one of them certified the key. Pass the alias of
    /// the device that just passed an attest challenge, so the key provably
    /// comes from it.
    /// </summary>
    public IReadOnlyList<string>? ExpectedDevices { get; init; }
}

/// <summary>
/// Options for <see cref="RootHeraldClient.VerifyAsync"/>.
/// </summary>
public sealed record AttestOptions
{
    /// <summary>
    /// The challenge handle from <see cref="RootHeraldChallenge.Nonce"/>. Required.
    /// The server finds the challenge by it and checks the proof was made over it.
    /// </summary>
    public required string Nonce { get; init; }

    /// <summary>
    /// Optional requested disclosure class for the returned device claim —
    /// <c>"verdict"</c>, <c>"pseudonymous"</c>, <c>"derived"</c>, or
    /// <c>"full"</c>. Sent on the wire as <c>requestedDisclosureClass</c>;
    /// omitted from the request when null, and the API key's ceiling
    /// (default <c>pseudonymous</c>) applies.
    /// </summary>
    public string? RequestedDisclosureClass { get; init; }

    /// <summary>
    /// The <see cref="ChallengeOptions.ExpectedKey"/> the challenge was issued
    /// with. The verdict must echo it under <c>expected.key</c>; a response
    /// that does not is <see cref="ExpectedNotEnforcedException"/>.
    /// </summary>
    public string? ExpectedKey { get; init; }

    /// <summary>
    /// The <see cref="ChallengeOptions.ExpectedDevices"/> the challenge was
    /// issued with. The verdict must echo them under <c>expected.devices</c>,
    /// and a non-failing verdict must name one of them; a response that does
    /// not is <see cref="ExpectedNotEnforcedException"/>.
    /// </summary>
    public IReadOnlyList<string>? ExpectedDevices { get; init; }
}

/// <summary>
/// What the challenge bound the verdict to, echoed by the server after it
/// enforced it (<c>verdict.expected</c>). Null when the challenge named nothing.
/// </summary>
/// <param name="Key">The <c>expectedKey</c> the challenge named.</param>
/// <param name="Devices">The <c>expectedDevices</c> the challenge named.</param>
public sealed record ExpectedBinding(string? Key, IReadOnlyList<string>? Devices);

/// <summary>
/// The key Root Herald registered, returned by
/// <see cref="RootHeraldClient.CertifyKeyAsync"/>. Store <see cref="KeyId"/>
/// and <see cref="Jwk"/> against <see cref="DeviceId"/>; a later request the
/// device signed is checked locally with
/// <see cref="RootHeraldClient.VerifyKeySignature"/>, with no call to Root Herald.
/// <para>
/// <see cref="KeyId"/> identifies an installation's credential, never a
/// device: bind accounts to <see cref="DeviceId"/>. Minting again for the same
/// purpose rotates the key under the same <see cref="KeyId"/>; a re-enrolled
/// installation gets new key ids.
/// </para>
/// </summary>
/// <param name="DeviceId">This tenant's alias for the device that holds the key; never relayed to the device.</param>
/// <param name="KeyId">Root Herald's id for this key, stable across rotations of the same purpose.</param>
/// <param name="Purpose"><see cref="KeyPurpose.Sign"/> or <see cref="KeyPurpose.Decrypt"/>.</param>
/// <param name="Alg"><c>ES256</c> / <c>RS256</c> for a sign key; <c>ECDH-ES</c> / <c>RSA-OAEP-256</c> for a decrypt key.</param>
/// <param name="Format">Decrypt keys only: <c>jwe</c> on TPM platforms, <c>apple-ecies</c> on macOS.</param>
/// <param name="Jwk">
/// The public key as a JWK: <c>{ kty: "EC", crv: "P-256", x, y }</c> or
/// <c>{ kty: "RSA", n, e }</c>, chosen by the device from what its TPM supports.
/// </param>
/// <param name="HardwareBound">
/// True when the key lives in a TPM and was certified by the installation's
/// attestation key; false on macOS, where the certification proves possession only.
/// </param>
/// <param name="CertifiedAt">When the certification was appraised.</param>
public sealed record CertifiedKey(
    string DeviceId,
    string KeyId,
    string Purpose,
    string Alg,
    string? Format,
    JsonObject Jwk,
    bool HardwareBound,
    DateTimeOffset CertifiedAt);

/// <summary>
/// The result of <see cref="RootHeraldClient.VerifyAsync"/>: the
/// normalised verdict and the full verdict node.
/// </summary>
public sealed record AttestResult
{
    /// <summary>
    /// The server's verdict token from <c>verdict.device.verdict</c>:
    /// <see cref="RootHerald.AspNetCore.Verdict.Pass"/>, <see cref="RootHerald.AspNetCore.Verdict.Warn"/>
    /// or <see cref="RootHerald.AspNetCore.Verdict.Fail"/>, the same vocabulary in every
    /// RootHerald SDK. A response carrying any other token is refused.
    /// </summary>
    public required string Verdict { get; init; }

    /// <summary>
    /// The full verdict object returned by the server, passed through verbatim:
    /// <c>acr</c>, <c>amr</c>, <c>authTime</c>, <c>expiresAt</c>, <c>userId</c>,
    /// <c>requestedAcrValues</c>, <c>expected</c> and <c>device</c>.
    /// <para>
    /// Under <c>device</c> (camelCase on the wire; a field gated by disclosure
    /// class is absent below it): <c>ueid</c>, <c>disclosureClass</c>,
    /// <c>earStatus</c>, <c>verdict</c>, <c>attestationType</c>,
    /// <c>attestedAt</c>, <c>quoteVerified</c>, <c>secureBootVerified</c>,
    /// <c>eventLogVerified</c>, <c>postureEvaluated</c>,
    /// <c>postureSkippedReason</c>, <c>platform</c>, <c>hardwareModel</c>,
    /// <c>tpmKind</c>, <c>chipAnchorId</c>, <c>identityAnchor</c>,
    /// <c>trustworthinessVector</c>, <c>hardwareGenuine</c>,
    /// <c>ekChainTrusted</c>, <c>sybilRisk</c>, <c>sybilResistance</c>,
    /// <c>returningDevice</c>, <c>identityAgeBucket</c>,
    /// <c>accountBindingBand</c>, <c>identityFirstSeen</c>,
    /// <c>attestationCount</c>, <c>accountBindingCount</c>,
    /// <c>possiblyRotated</c>, <c>identitiesOnAnchor</c>,
    /// <c>platformRotated</c>, <c>platformRotationsInWindow</c>,
    /// <c>bootChanged</c>, <c>bootChangedStages</c>, <c>bootChangeAccepted</c>,
    /// <c>bootBaselineAt</c>, and the advisory cohort fields <c>cohortKey</c>,
    /// <c>cohortScope</c>, <c>cohortPrevalence</c>, <c>cohortPrevalencePerPcr</c>,
    /// <c>cohortSampleSize</c>, <c>novelProfile</c>.
    /// </para>
    /// </summary>
    public required JsonNode VerdictData { get; init; }

    /// <summary>
    /// Assurance-claim URNs the device satisfied, from the top-level
    /// <c>assuranceClaimsMet</c> sibling of <c>verdict</c> on the wire. Empty
    /// when the server omits it.
    /// </summary>
    public IReadOnlyList<string> AssuranceClaimsMet { get; init; } = Array.Empty<string>();

    /// <summary>
    /// The attest-first / enroll-on-miss signal, from the top-level
    /// <c>enrollmentRequired</c> sibling of <c>verdict</c>. <c>true</c> when the
    /// quote did not resolve to a live installation of this tenant: the
    /// device must enroll, and the verdict is not to be trusted.
    /// </summary>
    public bool EnrollmentRequired { get; init; }

    /// <summary>
    /// The binding the challenge named, echoed by the server after it enforced
    /// it (<c>verdict.expected</c>). Null when the server sent none.
    /// </summary>
    public ExpectedBinding? Expected { get; init; }

    /// <summary>True when the verdict is <see cref="RootHerald.AspNetCore.Verdict.Pass"/>.</summary>
    public bool IsPass => Verdict == RootHerald.AspNetCore.Verdict.Pass;

    /// <summary>
    /// The device's alias, <c>verdict.device.ueid</c>: the same value
    /// <see cref="RelayActivateResponse.DeviceId"/> and
    /// <see cref="CertifiedKey.DeviceId"/> carry. Null when the disclosure
    /// class withheld it; fail closed on null if you key a decision on it.
    /// </summary>
    public string? DeviceId => VerdictData["device"]?["ueid"]?.GetValue<string>();
}

/// <summary>The verdict values the server emits at <c>verdict.device.verdict</c>.</summary>
public static class Verdict
{
    /// <summary>The device satisfied the policy.</summary>
    public const string Pass = "pass";

    /// <summary>The device passed with reduced assurance; the policy says whether to proceed.</summary>
    public const string Warn = "warn";

    /// <summary>The device did not satisfy the policy, or is not enrolled (see <see cref="AttestResult.EnrollmentRequired"/>).</summary>
    public const string Fail = "fail";

    internal static readonly string[] All = [Pass, Warn, Fail];
}

/// <summary>
/// Server → server Background-Check client.
/// <para>
/// The customer's client does local TPM work and hands the customer's own
/// server opaque blobs (no keys, no Root Herald contact). The server uses this
/// client, authenticated with its <c>rh_sk_</c> secret key, to drive three
/// ceremonies of two legs each: enroll
/// (<see cref="RelayEnrollAsync(EnrollRequestBlob, CancellationToken)"/> /
/// <see cref="RelayActivateAsync"/>), mint a key
/// (<see cref="IssueKeyChallengeAsync"/> / <see cref="CertifyKeyAsync"/>) and
/// attest (<see cref="IssueChallengeAsync"/> / <see cref="VerifyAsync"/>).
/// </para>
/// Pure managed C# over <see cref="HttpClient"/>; no native dependencies.
/// </summary>
public sealed class RootHeraldClient
{
    /// <summary>Production Root Herald API base URL.</summary>
    public const string DefaultBaseUrl = "https://rootherald.io";

    private const string SecretKeyPrefix = "rh_sk_";

    /// <summary>
    /// Per-request timeout of the <see cref="HttpClient"/> this client creates
    /// when none is supplied: 30 seconds, the same in every RootHerald server
    /// SDK. A caller-supplied client keeps its own <see cref="HttpClient.Timeout"/>.
    /// </summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    // Server error codes that tell apart the refusals sharing one status.
    private const string CodeActivationRefused = "activation_refused";
    private const string CodeAdmissionRefused = "admission_refused";
    private const string CodeUnknownPolicy = "unknown_policy";
    private const string CodeKeyRotationConflict = "key_rotation_conflict";
    private const string CodeInvalidAsk = "invalid_ask";
    private const string CodeBudgetExhausted = "budget_exhausted";

    // Marks a 429 as the budget, whatever the body says.
    private const string QuotaHeader = "X-RootHerald-Quota";

    private const int MinRsaModulusBytes = 256;

    private static readonly string[] EcAlgs = ["ES256", "ECDH-ES"];
    private static readonly string[] RsaAlgs = ["RS256", "RSA-OAEP-256"];
    private static readonly string[] KeyFormats = ["jwe", "apple-ecies"];

    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly Uri _baseUri;
    private readonly string _secretKey;

    /// <summary>
    /// Create a Background-Check client.
    /// </summary>
    /// <param name="secretKey">
    /// Your Root Herald secret key (<c>rh_sk_…</c>). Required. Used server-side
    /// as a Bearer token; any value not starting with <c>rh_sk_</c> is rejected.
    /// </param>
    /// <param name="baseUrl">API base URL. Defaults to the production API.</param>
    /// <param name="httpClient">
    /// Optional <see cref="HttpClient"/> (DI / IHttpClientFactory / tests). When
    /// supplied, the caller owns its lifetime and its <see cref="HttpClient.Timeout"/>;
    /// otherwise an internal one with <see cref="DefaultTimeout"/> is used.
    /// </param>
    public RootHeraldClient(string secretKey, string? baseUrl = null, HttpClient? httpClient = null)
    {
        if (string.IsNullOrEmpty(secretKey))
            throw new ArgumentException("a secret key (rh_sk_…) is required", nameof(secretKey));
        if (!secretKey.StartsWith(SecretKeyPrefix, StringComparison.Ordinal))
            throw new ArgumentException(
                "RootHerald secret key must start with rh_sk_",
                nameof(secretKey));

        var resolvedBase = (baseUrl ?? DefaultBaseUrl).TrimEnd('/') + "/";
        if (!Uri.TryCreate(resolvedBase, UriKind.Absolute, out var baseUri)
            || baseUri.Scheme != Uri.UriSchemeHttps)
        {
            // A typo'd or http:// base URL would send the full-privilege rh_sk_
            // secret in cleartext. Loopback is exempt so the local docker stack
            // still works.
            if (baseUri is null || !baseUri.IsLoopback)
                throw new ArgumentException(
                    $"baseUrl must be an absolute https URL (got '{resolvedBase}').",
                    nameof(baseUrl));
        }

        _ownsHttp = httpClient is null;
        _http = httpClient ?? new HttpClient { Timeout = DefaultTimeout };
        _baseUri = baseUri!;
        _secretKey = secretKey;

        // Auth is attached per request, never onto the client: an injected
        // HttpClient is shared with the caller's other hosts, and its own
        // BaseAddress must not redirect the secret and the evidence elsewhere.
    }

    /// <summary>
    /// <c>POST /api/v1/attest/challenge</c> — mint a challenge carrying the
    /// given ask. Relay <see cref="RootHeraldChallenge.Challenge"/> to the
    /// client verbatim; it parses the ask from it and produces matching
    /// evidence, which the server submits with <see cref="VerifyAsync"/> using
    /// <see cref="RootHeraldChallenge.Nonce"/>.
    /// <para>
    /// Policies bind to the API key, not to this call. The server resolves the
    /// policy from the key that mints the challenge and pins it on the
    /// challenge; a <c>policy</c> field in a hand-built body is refused with
    /// 400 <c>policy_bound_to_key</c>.
    /// </para>
    /// </summary>
    /// <param name="options">The ask and the expected key or devices. Null asks for identity + posture.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    public async Task<RootHeraldChallenge> IssueChallengeAsync(
        ChallengeOptions? options = null, CancellationToken cancellationToken = default)
    {
        var body = new JsonObject();
        if (options?.Ask is { Count: > 0 } ask)
            body["ask"] = ToJsonArray(ask);
        if (options?.ExpectedKey is { } expectedKey)
            body["expectedKey"] = RequireNonEmpty(expectedKey, "ExpectedKey", nameof(options));
        if (options?.ExpectedDevices is { } expectedDevices)
            body["expectedDevices"] = ToJsonArray(RequireAliasList(expectedDevices, "ExpectedDevices", nameof(options)));

        var data = await PostAsync("api/v1/attest/challenge", body, cancellationToken)
            .ConfigureAwait(false);
        var nonce = data["nonce"]?.GetValue<string>();
        var challenge = data["challenge"]?.GetValue<string>();
        var expiresAt = data["expiresAt"]?.GetValue<string>();
        if (string.IsNullOrEmpty(nonce) || string.IsNullOrEmpty(challenge) || string.IsNullOrEmpty(expiresAt))
            throw new RootHeraldApiException(200, "challenge response missing nonce/challenge/expiresAt");
        return new RootHeraldChallenge(nonce, challenge, expiresAt);
    }

    /// <summary>
    /// <c>POST /api/v1/attest/verify</c> — submit the opaque evidence blob
    /// for server-side appraisal and return the verdict.
    /// <para>
    /// An un-enrolled / failing device is NOT an error — it returns a normal
    /// <see cref="AttestResult"/> carrying a <c>"fail"</c>/<c>"warn"</c>
    /// verdict. Only protocol/auth/budget problems raise a
    /// <see cref="RootHeraldApiException"/>.
    /// </para>
    /// <para>
    /// When the challenge named <see cref="ChallengeOptions.ExpectedKey"/> or
    /// <see cref="ChallengeOptions.ExpectedDevices"/>, pass the same values in
    /// <paramref name="options"/>: the verdict must echo them under
    /// <c>expected</c>, and a response that does not is refused with
    /// <see cref="ExpectedNotEnforcedException"/>.
    /// </para>
    /// </summary>
    /// <param name="evidence">
    /// Opaque blob from the client collector, as a <see cref="JsonNode"/>; passed
    /// through verbatim.
    /// </param>
    /// <param name="options">The challenge nonce, an optional disclosure class, and the binding the challenge named.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    public async Task<AttestResult> VerifyAsync(
        JsonNode evidence, AttestOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrEmpty(options.Nonce))
            throw new ArgumentException("AttestOptions.Nonce is required (from IssueChallengeAsync)", nameof(options));
        var expectedKey = options.ExpectedKey is { } k ? RequireNonEmpty(k, "ExpectedKey", nameof(options)) : null;
        var expectedDevices = options.ExpectedDevices is { } d ? RequireAliasList(d, "ExpectedDevices", nameof(options)) : null;

        var body = new JsonObject
        {
            ["nonce"] = options.Nonce,
            // evidence is opaque; embed verbatim (DeepClone detaches it from any parent).
            ["evidence"] = evidence.DeepClone(),
        };
        if (options.RequestedDisclosureClass is not null)
            body["requestedDisclosureClass"] = options.RequestedDisclosureClass;

        var data = await PostAsync("api/v1/attest/verify", body, cancellationToken)
            .ConfigureAwait(false);
        var verdictNode = data["verdict"];
        if (verdictNode is not JsonObject)
            throw new RootHeraldApiException(200, "verify response missing verdict");

        // The pass/fail token and per-device appraisal fields (earStatus,
        // attestationType, quoteVerified, …) live under verdict.device.
        var verdict = ParseVerdict(verdictNode["device"]?["verdict"]);

        var result = new AttestResult
        {
            Verdict = verdict,
            VerdictData = verdictNode,
            AssuranceClaimsMet = ReadStringArray(data["assuranceClaimsMet"]),
            EnrollmentRequired = data["enrollmentRequired"]?.GetValue<bool>() ?? false,
            Expected = ReadExpected(verdictNode["expected"]),
        };

        if (expectedKey is not null || expectedDevices is not null)
            RequireExpectedEnforced(result, expectedKey, expectedDevices);
        return result;
    }

    /// <summary>
    /// <c>POST /api/v1/keys/challenge</c> — mint a single-use key challenge
    /// for a purpose. Relay <see cref="RootHeraldKeyChallenge.KeyChallenge"/>
    /// to the client verbatim; its <c>MintKey</c> answers with a
    /// certification, which the server submits with
    /// <see cref="CertifyKeyAsync"/> using <see cref="RootHeraldKeyChallenge.Nonce"/>.
    /// <para>
    /// Refused with 422 <c>key_disclosure_too_low</c> when the API key's
    /// disclosure ceiling is below <c>pseudonymous</c>: a key whose id could
    /// never be returned is never minted.
    /// </para>
    /// </summary>
    /// <param name="options">The purpose and, optionally, the devices allowed to certify.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    public async Task<RootHeraldKeyChallenge> IssueKeyChallengeAsync(
        KeyChallengeOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (Array.IndexOf(KeyPurpose.All, options.Purpose) < 0)
            throw new ArgumentException(
                $"KeyChallengeOptions.Purpose must be one of {string.Join("/", KeyPurpose.All)}", nameof(options));

        var body = new JsonObject { ["purpose"] = options.Purpose };
        if (options.ExpectedDevices is { } expectedDevices)
            body["expectedDevices"] = ToJsonArray(RequireAliasList(expectedDevices, "ExpectedDevices", nameof(options)));

        var data = await PostAsync("api/v1/keys/challenge", body, cancellationToken)
            .ConfigureAwait(false);
        var nonce = data["nonce"]?.GetValue<string>();
        var keyChallenge = data["keyChallenge"]?.GetValue<string>();
        var expiresAt = data["expiresAt"]?.GetValue<string>();
        if (string.IsNullOrEmpty(nonce) || string.IsNullOrEmpty(keyChallenge) || string.IsNullOrEmpty(expiresAt))
            throw new RootHeraldApiException(200, "key challenge response missing nonce/keyChallenge/expiresAt");
        return new RootHeraldKeyChallenge(nonce, keyChallenge, expiresAt);
    }

    /// <summary>
    /// <c>POST /api/v1/keys/certify</c> — relay the client's <c>MintKey</c>
    /// output under the key challenge's nonce and return the key Root Herald
    /// registered: its <see cref="CertifiedKey.KeyId"/>, public
    /// <see cref="CertifiedKey.Jwk"/>, <see cref="CertifiedKey.Alg"/>, and the
    /// <see cref="CertifiedKey.DeviceId"/> of the installation that certified
    /// it. Later signatures are checked locally with <see cref="VerifyKeySignature"/>.
    /// <para>
    /// The certification is relayed verbatim, whichever platform shape it is:
    /// <c>{ publicArea, attest, signature }</c> from a TPM, or a
    /// <c>platform</c>-tagged body from macOS or iOS. The key is the call's
    /// only output, so a malformed one is refused with
    /// <see cref="RootHeraldApiException"/> rather than returned half-parsed.
    /// </para>
    /// </summary>
    /// <param name="nonce">The key challenge handle from <see cref="RootHeraldKeyChallenge.Nonce"/>.</param>
    /// <param name="certification">The client's <c>MintKey</c> output, as a <see cref="JsonNode"/>.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    public async Task<CertifiedKey> CertifyKeyAsync(
        string nonce, JsonNode certification, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(nonce))
            throw new ArgumentException("nonce is required (from IssueKeyChallengeAsync)", nameof(nonce));
        ArgumentNullException.ThrowIfNull(certification);
        if (certification is not JsonObject obj || !IsWellFormedCertification(obj))
            throw new ArgumentException(
                "certification must be the client's MintKey output: { publicArea, attest, signature } on a TPM, or the platform form from macOS / iOS",
                nameof(certification));

        var body = new JsonObject
        {
            ["nonce"] = nonce,
            ["certification"] = certification.DeepClone(),
        };
        var data = await PostAsync("api/v1/keys/certify", body, cancellationToken)
            .ConfigureAwait(false);
        return ReadCertifiedKey(data);
    }

    /// <summary>
    /// Enroll relay — leg 1. <c>POST /api/v1/attest/enroll</c>.
    /// <para>
    /// Relays the client's <c>EnrollBegin()</c> blob to Root Herald with the
    /// <c>rh_sk_</c> secret and returns the
    /// <see cref="RelayEnrollResult.Challenge"/> to hand to the client's
    /// <c>EnrollComplete</c>, whose result goes to
    /// <see cref="RelayActivateAsync"/>. The body is relayed whole, including
    /// fields this SDK does not model.
    /// </para>
    /// <para>
    /// A TPM body must carry the nested <see cref="EnrollRequestBlob.AttestationKey"/>;
    /// a flat one with <see cref="EnrollRequestBlob.AkPublicArea"/> is the 7.0
    /// shape and is refused locally with <see cref="ArgumentException"/> before
    /// any request. Admission runs under the identity policy bound to the API
    /// key, so a device whose TPM class can never satisfy it is refused before
    /// it gets an attestation key: <see cref="AdmissionRefusedException"/>, with
    /// the class in the message.
    /// </para>
    /// </summary>
    /// <param name="enrollRequestBlob">The opaque enroll-begin blob from the client.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    public Task<RelayEnrollResult> RelayEnrollAsync(
        EnrollRequestBlob enrollRequestBlob, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(enrollRequestBlob);
        var node = JsonSerializer.SerializeToNode(enrollRequestBlob) as JsonObject
            ?? throw new ArgumentException("enroll request blob did not serialize to an object", nameof(enrollRequestBlob));
        return RelayEnrollCoreAsync(node, nameof(enrollRequestBlob), cancellationToken);
    }

    /// <summary>
    /// Enroll relay — leg 1, from the client's body as JSON. The same as
    /// <see cref="RelayEnrollAsync(EnrollRequestBlob, CancellationToken)"/>
    /// with the body posted as-is after the shape check, for a backend that
    /// receives the device's JSON and need not model it.
    /// </summary>
    /// <param name="enrollRequestBlob">The client's <c>EnrollBegin()</c> body.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    public Task<RelayEnrollResult> RelayEnrollAsync(
        JsonObject enrollRequestBlob, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(enrollRequestBlob);
        return RelayEnrollCoreAsync(enrollRequestBlob, nameof(enrollRequestBlob), cancellationToken);
    }

    private async Task<RelayEnrollResult> RelayEnrollCoreAsync(
        JsonObject blob, string paramName, CancellationToken cancellationToken)
    {
        var platform = ReadString(blob["platform"]);
        var ios = platform == "ios";
        if (!IsWellFormedEnrollBlob(blob, platform))
            throw new ArgumentException(
                "enroll request blob requires ekPublicKey with attestationKey { publicArea, parentPublicArea, qualifiedName } (windows/linux), ekPublicKey with akPublicArea (macos), or iosKeyId, iosAttestationObject and nonce (ios)",
                paramName);

        var data = await PostAsync("api/v1/attest/enroll", blob, cancellationToken)
            .ConfigureAwait(false);
        if (data is not JsonObject body)
            throw new RootHeraldApiException(201, "enroll response is not an object");

        // The attestation object is the whole proof on iOS; the server answers
        // {} because the device has nothing to activate.
        if (ios && body.Count == 0)
            return new RelayEnrollResult { Challenge = null };

        var enrollmentId = body["enrollmentId"]?.GetValue<string>();
        var credentialBlob = body["credentialBlob"]?.GetValue<string>();
        var encryptedSecret = body["encryptedSecret"]?.GetValue<string>();
        var challengeNonce = body["challengeNonce"]?.GetValue<string>();
        var tpm = !string.IsNullOrEmpty(credentialBlob) && !string.IsNullOrEmpty(encryptedSecret);
        if (string.IsNullOrEmpty(enrollmentId) || !(tpm || !string.IsNullOrEmpty(challengeNonce)))
            throw new RootHeraldApiException(
                201, "enroll response missing enrollmentId and credentialBlob/encryptedSecret or challengeNonce");

        return new RelayEnrollResult
        {
            Challenge = new EnrollActivationChallenge
            {
                EnrollmentId = enrollmentId,
                CredentialBlob = credentialBlob,
                EncryptedSecret = encryptedSecret,
                ChallengeNonce = challengeNonce,
            },
        };
    }

    /// <summary>
    /// Enroll relay — leg 2. <c>POST /api/v1/attest/activate</c>.
    /// <para>
    /// Relays the client's <c>EnrollComplete()</c> blob (the decrypted credential
    /// secret, or the enclave signature on macOS) to Root Herald, completing
    /// the enrollment the <c>enrollmentId</c> names. Every TPM and macOS
    /// enroll leads here: each activation creates a new installation of the
    /// device, with its own attestation key.
    /// </para>
    /// Returns the terminal <c>{ deviceId, status, enrolledAt }</c> body;
    /// <see cref="RelayActivateResponse.DeviceId"/> is the load-bearing field the
    /// backend maps to its user, and must never be relayed to the device.
    /// </summary>
    /// <param name="activationResponse">The opaque enroll-complete blob from the client.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    public async Task<RelayActivateResponse> RelayActivateAsync(
        EnrollActivationResponse activationResponse, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(activationResponse);
        if (string.IsNullOrEmpty(activationResponse.EnrollmentId) ||
            (string.IsNullOrEmpty(activationResponse.DecryptedSecret) &&
             string.IsNullOrEmpty(activationResponse.Signature)))
            throw new ArgumentException(
                "activation response requires enrollmentId and decryptedSecret or signature", nameof(activationResponse));

        var data = await PostAsync("api/v1/attest/activate", activationResponse, cancellationToken)
            .ConfigureAwait(false);
        var deviceId = data["deviceId"]?.GetValue<string>();
        if (string.IsNullOrEmpty(deviceId))
            throw new RootHeraldApiException(200, "activate response missing deviceId");

        return new RelayActivateResponse
        {
            DeviceId = deviceId,
            Status = data["status"]?.GetValue<string>(),
            EnrolledAt = data["enrolledAt"]?.GetValue<string>(),
        };
    }

    /// <summary>
    /// Checks a signature made by a key Root Herald certified
    /// (<see cref="CertifiedKey.Jwk"/>) over <paramref name="message"/>, with
    /// no call to Root Herald. The customer stores the JWK at certification
    /// time and checks each later request locally.
    /// <para>
    /// An EC P-256 key checks ES256: ECDSA over SHA-256(message), in either
    /// the raw <c>r||s</c> form (64 bytes, as a TPM emits) or ASN.1 DER. An
    /// RSA key checks RS256: PKCS#1 v1.5 over SHA-256, a modulus of at least
    /// 2048 bits and a signature of exactly the modulus length. Returns false
    /// for anything it cannot verify — an unsupported key, a point off the
    /// curve, or a malformed signature — and never throws.
    /// </para>
    /// A signature proves possession of the key at that moment, not how the
    /// machine booted; run an attest challenge for that.
    /// </summary>
    public static bool VerifyKeySignature(JsonObject jwk, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (jwk is null || signature.IsEmpty) return false;
        try
        {
            return ReadString(jwk["kty"]) switch
            {
                "EC" => VerifyEs256(jwk, message, signature),
                "RSA" => VerifyRs256(jwk, message, signature),
                _ => false,
            };
        }
        catch (Exception)
        {
            // A malformed key or signature is a false, not a fault.
            return false;
        }
    }

    private static bool VerifyEs256(JsonObject jwk, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (ReadString(jwk["crv"]) != "P-256") return false;
        var x = DecodeBase64Url(ReadString(jwk["x"]));
        var y = DecodeBase64Url(ReadString(jwk["y"]));
        if (x is not { Length: 32 } || y is not { Length: 32 }) return false;

        // ECDsa.Create validates the point is on the curve and throws otherwise.
        using var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = x, Y = y },
        });

        var format = signature.Length == 64
            ? DSASignatureFormat.IeeeP1363FixedFieldConcatenation
            : DSASignatureFormat.Rfc3279DerSequence;
        return ecdsa.VerifyData(message, signature, HashAlgorithmName.SHA256, format);
    }

    private static bool VerifyRs256(JsonObject jwk, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        var n = DecodeBase64Url(ReadString(jwk["n"]));
        var e = DecodeBase64Url(ReadString(jwk["e"]));
        if (n is null || e is null || e.Length == 0) return false;
        // JWK integers are unsigned big-endian with no leading zero; the
        // modulus length in bytes is the signature length PKCS#1 demands.
        if (n.Length < MinRsaModulusBytes || n[0] == 0 || signature.Length != n.Length) return false;

        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters { Modulus = n, Exponent = e });
        return rsa.VerifyData(message, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    /// <summary>
    /// Decodes one base64url JWK field. JWK fields are unpadded, but padding
    /// and the standard alphabet are tolerated.
    /// </summary>
    private static byte[]? DecodeBase64Url(string? value)
    {
        if (string.IsNullOrEmpty(value)) return null;
        var s = value.TrimEnd('=').Replace('-', '+').Replace('_', '/');
        s = s.PadRight(s.Length + (4 - s.Length % 4) % 4, '=');
        try
        {
            return Convert.FromBase64String(s);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// <summary>
    /// The 8.0 TPM body nests the AK; macOS stays flat; iOS is its own shape.
    /// A flat TPM body is the 7.0 shape and is refused here rather than
    /// relayed: the server would answer <c>wire_version_unsupported</c>
    /// anyway, and refusing locally keeps the message specific.
    /// </summary>
    private static bool IsWellFormedEnrollBlob(JsonObject blob, string? platform)
    {
        switch (platform)
        {
            case "ios":
                return HasString(blob, "iosKeyId") && HasString(blob, "iosAttestationObject") && HasString(blob, "nonce");
            case "macos":
                return HasString(blob, "ekPublicKey") && HasString(blob, "akPublicArea") && !blob.ContainsKey("attestationKey");
            case "windows":
            case "linux":
                return HasString(blob, "ekPublicKey")
                    && blob["attestationKey"] is JsonObject ak
                    && HasString(ak, "publicArea") && HasString(ak, "parentPublicArea") && HasString(ak, "qualifiedName")
                    && !blob.ContainsKey("akPublicArea");
            default:
                return false;
        }
    }

    /// <summary>
    /// The certification is per platform and relayed verbatim, so only its
    /// outer shape is checked: a TPM certification's three base64 strings, or
    /// a platform-tagged body from macOS or iOS.
    /// </summary>
    private static bool IsWellFormedCertification(JsonObject certification)
    {
        if (HasString(certification, "platform")) return true;
        return HasString(certification, "publicArea") && HasString(certification, "attest") && HasString(certification, "signature");
    }

    private static bool HasString(JsonObject obj, string key) => !string.IsNullOrEmpty(ReadString(obj[key]));

    /// <summary>The node's string value, or null when it is absent or not a string.</summary>
    private static string? ReadString(JsonNode? node) =>
        node is JsonValue value && value.TryGetValue<string>(out var s) ? s : null;

    /// <summary>
    /// Reads a <c>/keys/certify</c> response. The JWK family must match
    /// <c>alg</c>: an EC key signs ES256 or agrees ECDH-ES, an RSA key signs
    /// RS256 or wraps RSA-OAEP-256. Anything else is refused rather than
    /// surfaced half-parsed: a caller that then called
    /// <see cref="VerifyKeySignature"/> with it would silently get false.
    /// </summary>
    private static CertifiedKey ReadCertifiedKey(JsonNode node)
    {
        static RootHeraldApiException Refuse(string why) => new(200, $"certify response {why}");

        if (node is not JsonObject obj) throw Refuse("is not an object");
        var deviceId = ReadString(obj["deviceId"]);
        if (string.IsNullOrEmpty(deviceId)) throw Refuse("missing deviceId");
        var keyId = ReadString(obj["keyId"]);
        if (string.IsNullOrEmpty(keyId)) throw Refuse("missing keyId");
        var purpose = ReadString(obj["purpose"]);
        if (purpose is null || Array.IndexOf(KeyPurpose.All, purpose) < 0)
            throw Refuse($"purpose is not one of {string.Join("/", KeyPurpose.All)}");
        if (obj["hardwareBound"] is not JsonValue hb || !hb.TryGetValue<bool>(out var hardwareBound))
            throw Refuse("missing hardwareBound");
        if (!DateTimeOffset.TryParse(ReadString(obj["certifiedAt"]), null,
                System.Globalization.DateTimeStyles.RoundtripKind, out var certifiedAt))
            throw Refuse("certifiedAt is not a timestamp");

        var jwk = ReadJwk(obj["jwk"]) ?? throw Refuse("jwk is not an EC P-256 or RSA public key");
        var kty = ReadString(jwk["kty"]);
        var alg = ReadString(obj["alg"]);
        var algs = kty == "EC" ? EcAlgs : RsaAlgs;
        if (alg is null || Array.IndexOf(algs, alg) < 0)
            throw Refuse($"alg '{alg}' does not fit a {kty} key");
        var format = obj["format"] is null ? null : ReadString(obj["format"]);
        if (obj["format"] is not null && (format is null || Array.IndexOf(KeyFormats, format) < 0))
            throw Refuse($"format is not one of {string.Join("/", KeyFormats)}");

        return new CertifiedKey(deviceId, keyId, purpose, alg, format, jwk, hardwareBound, certifiedAt);
    }

    private static JsonObject? ReadJwk(JsonNode? node)
    {
        if (node is not JsonObject obj) return null;
        var kty = ReadString(obj["kty"]);
        if (kty == "EC" && ReadString(obj["crv"]) == "P-256" && HasString(obj, "x") && HasString(obj, "y"))
            return new JsonObject { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = obj["x"]!.GetValue<string>(), ["y"] = obj["y"]!.GetValue<string>() };
        if (kty == "RSA" && HasString(obj, "n") && HasString(obj, "e"))
            return new JsonObject { ["kty"] = "RSA", ["n"] = obj["n"]!.GetValue<string>(), ["e"] = obj["e"]!.GetValue<string>() };
        return null;
    }

    private static ExpectedBinding? ReadExpected(JsonNode? node)
    {
        if (node is not JsonObject obj) return null;
        var key = ReadString(obj["key"]);
        var devices = obj["devices"] is JsonArray ? ReadStringArray(obj["devices"]) : null;
        return new ExpectedBinding(key, devices);
    }

    /// <summary>
    /// A verdict is only as bound as the server says it enforced. The API
    /// ignores unknown JSON fields, so a server that predates the binding
    /// would accept any device and answer a verdict with no <c>expected</c>
    /// block; comparing the echo with what was asked turns that silence into
    /// a refusal.
    /// </summary>
    private static void RequireExpectedEnforced(AttestResult result, string? expectedKey, IReadOnlyList<string>? expectedDevices)
    {
        static ExpectedNotEnforcedException Refuse(string what) =>
            new($"verify response did not echo the {what} the challenge named; the binding was not enforced");

        if (expectedKey is not null && result.Expected?.Key != expectedKey)
            throw Refuse("ExpectedKey");
        if (expectedDevices is not null)
        {
            var echoed = result.Expected?.Devices;
            if (echoed is null || !echoed.ToHashSet(StringComparer.Ordinal).SetEquals(expectedDevices))
                throw Refuse("ExpectedDevices");
            if (result.Verdict != RootHerald.AspNetCore.Verdict.Fail && result.DeviceId is { } ueid && !expectedDevices.Contains(ueid))
                throw Refuse("ExpectedDevices");
        }
    }

    private static string RequireNonEmpty(string value, string field, string paramName)
    {
        if (string.IsNullOrEmpty(value))
            throw new ArgumentException($"{field} must be a non-empty string", paramName);
        return value;
    }

    private static IReadOnlyList<string> RequireAliasList(IReadOnlyList<string> value, string field, string paramName)
    {
        if (value.Count == 0 || value.Any(string.IsNullOrEmpty))
            throw new ArgumentException($"{field} must be a non-empty list of non-empty strings", paramName);
        return value;
    }

    private static JsonArray ToJsonArray(IEnumerable<string> values) =>
        new(values.Select(v => (JsonNode?)JsonValue.Create(v)).ToArray());

    /// <summary>
    /// Issues an authenticated JSON POST and returns the parsed JSON body, mapping
    /// non-2xx responses to the typed <see cref="RootHeraldApiException"/> taxonomy.
    /// </summary>
    private async Task<JsonNode> PostAsync(string path, object body, CancellationToken cancellationToken)
    {
        using var response = await RawPostAsync(path, body, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            throw await ToApiExceptionAsync(response, cancellationToken).ConfigureAwait(false);

        var node = await response.Content.ReadFromJsonAsync<JsonNode>(cancellationToken).ConfigureAwait(false);
        if (node is null)
            throw new RootHeraldApiException((int)response.StatusCode, "empty Root Herald response");
        return node;
    }

    /// <summary>
    /// Issues an authenticated JSON POST and returns the raw response. Status
    /// interpretation is left to the caller.
    /// </summary>
    private Task<HttpResponseMessage> RawPostAsync(string path, object body, CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, new Uri(_baseUri, path))
        {
            Content = JsonContent.Create(body),
        };
        request.Headers.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _secretKey);
        return _http.SendAsync(request, cancellationToken);
    }

    private static async Task<RootHeraldApiException> ToApiExceptionAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        string? errorCode = null;
        string? message = null;
        int? retryAfterSeconds = null;
        RefusingBudget? budget = null;
        try
        {
            var node = await response.Content.ReadFromJsonAsync<JsonNode>(cancellationToken).ConfigureAwait(false);
            if (node is JsonObject obj)
            {
                errorCode = obj["error"]?.GetValue<string>();
                message = obj["message"]?.GetValue<string>()
                    ?? obj["detail"]?.GetValue<string>()
                    ?? obj["error_description"]?.GetValue<string>();
                if (obj["retryAfterSeconds"] is JsonValue retry && retry.TryGetValue<int>(out var seconds))
                    retryAfterSeconds = seconds;
                if (obj["budget"] is JsonObject b && HasString(b, "id") && HasString(b, "name"))
                    budget = new RefusingBudget(b["id"]!.GetValue<string>(), b["name"]!.GetValue<string>());
            }
        }
        catch (JsonException)
        {
            // non-JSON body — fall through to status-based mapping
        }
        if (response.Headers.RetryAfter?.Delta is { } delta)
            retryAfterSeconds = (int)delta.TotalSeconds;

        var status = (int)response.StatusCode;
        return response.StatusCode switch
        {
            HttpStatusCode.Unauthorized when errorCode == CodeActivationRefused =>
                new ActivationRefusedException(message ?? "activation refused", errorCode),
            HttpStatusCode.Unauthorized => new InvalidSecretKeyException(message ?? "invalid secret key", errorCode),
            HttpStatusCode.UnprocessableEntity when errorCode == CodeAdmissionRefused =>
                new AdmissionRefusedException(message ?? "enrollment refused for this device class", errorCode),
            HttpStatusCode.UnprocessableEntity when errorCode is null or CodeUnknownPolicy =>
                new UnknownPolicyException(message ?? "unknown policy", errorCode),
            HttpStatusCode.Conflict when errorCode != CodeKeyRotationConflict =>
                new ChallengeException(message ?? "challenge invalid or expired", errorCode),
            HttpStatusCode.BadRequest when errorCode == CodeInvalidAsk =>
                new InvalidAskException(message ?? "invalid ask", errorCode),
            HttpStatusCode.BadRequest => new InvalidEvidenceException(message ?? "invalid evidence", errorCode),
            HttpStatusCode.TooManyRequests when errorCode == CodeBudgetExhausted || response.Headers.Contains(QuotaHeader) =>
                new QuotaExceededException(message ?? "budget exhausted", errorCode, budget),
            HttpStatusCode.TooManyRequests =>
                new RateLimitedException(message ?? "rate limited", errorCode, retryAfterSeconds),
            _ => new RootHeraldApiException(status, message ?? $"Root Herald API error (HTTP {status})", errorCode),
        };
    }

    /// <summary>
    /// Read the <c>verdict.device.verdict</c> token. Anything outside the three
    /// values the server emits is a malformed response, never a guessed verdict.
    /// </summary>
    private static string ParseVerdict(JsonNode? node)
    {
        var raw = node is JsonValue value && value.TryGetValue<string>(out var s) ? s.Trim().ToLowerInvariant() : null;
        if (raw is not null && Array.IndexOf(RootHerald.AspNetCore.Verdict.All, raw) >= 0)
            return raw;
        throw new RootHeraldApiException(200,
            $"verify response verdict.device.verdict is not pass/warn/fail (got {node?.ToJsonString() ?? "null"})");
    }

    /// <summary>Reads a JSON string array, tolerating a null/absent/non-array node.</summary>
    private static IReadOnlyList<string> ReadStringArray(JsonNode? node)
    {
        if (node is not JsonArray array)
            return Array.Empty<string>();

        var values = new List<string>(array.Count);
        foreach (var item in array)
        {
            if (item is JsonValue value && value.TryGetValue<string>(out var s))
                values.Add(s);
        }
        return values;
    }
}
