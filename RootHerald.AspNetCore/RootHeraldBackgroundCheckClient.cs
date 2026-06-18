using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace RootHerald.AspNetCore;

/// <summary>
/// A relay-friendly nonce minted by
/// <see cref="RootHeraldBackgroundCheckClient.CreateChallengeAsync"/>.
/// Relay <see cref="Nonce"/> to the dumb client; it quotes over it and returns
/// an opaque evidence blob, which the server submits to
/// <see cref="RootHeraldBackgroundCheckClient.AttestAsync"/> using
/// <see cref="ChallengeId"/>.
/// </summary>
public sealed record RootHeraldChallenge(string ChallengeId, string Nonce, string ExpiresAt);

/// <summary>
/// Options for <see cref="RootHeraldBackgroundCheckClient.AttestAsync"/>.
/// </summary>
public sealed record AttestOptions
{
    /// <summary>The single-use challenge id from CreateChallengeAsync. Required.</summary>
    public required string ChallengeId { get; init; }

    /// <summary>
    /// Caller-named policy: a tenant-owned policy id/name or a
    /// <c>rootherald:builtin:*</c> name. Unknown/foreign names fail closed (422).
    /// </summary>
    public string? Policy { get; init; }

    /// <summary>Opt-in signed EAT (JWT) output. Default false.</summary>
    public bool ReturnToken { get; init; }
}

/// <summary>
/// The result of <see cref="RootHeraldBackgroundCheckClient.AttestAsync"/>: the
/// normalised verdict, the full verdict node, and an optional signed EAT (JWT)
/// when <see cref="AttestOptions.ReturnToken"/> was requested.
/// </summary>
public sealed record AttestResult
{
    /// <summary>Normalised verdict: <c>"allow"</c>, <c>"deny"</c>, or <c>"review"</c>.</summary>
    public required string Verdict { get; init; }

    /// <summary>
    /// The full verdict object returned by the server, passed through verbatim.
    /// <para>
    /// In addition to the per-device appraisal under <c>device</c>, when a
    /// quote-bound event log was supplied the server populates ADDITIVE,
    /// advisory-only cohort fields on <c>device</c> (camelCase on the wire;
    /// absent/null otherwise) — never a trust gate:
    /// <c>cohortKey</c> (string), <c>cohortScope</c> ("global"|"tenant-fleet"),
    /// <c>cohortPrevalence</c> (number|null),
    /// <c>cohortPrevalencePerPcr</c> (object), <c>cohortSampleSize</c> (number|null),
    /// <c>novelProfile</c> (bool|null). Because the verdict is exposed as a raw
    /// <see cref="JsonNode"/>, these flow through with no type change.
    /// </para>
    /// </summary>
    public required JsonNode VerdictData { get; init; }

    /// <summary>The signed EAT, or <c>null</c> if not requested/returned.</summary>
    public string? Token { get; init; }

    /// <summary>True when the verdict is <c>"allow"</c>.</summary>
    public bool IsAllowed => string.Equals(Verdict, "allow", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Server → server Background-Check client.
/// <para>
/// The customer's dumb client collects an opaque evidence blob (no keys, no
/// Root Herald contact) and hands it to the customer's own server. The server
/// uses this client, authenticated with its <c>rh_sk_</c> secret key, to mint a
/// relay-friendly nonce (<see cref="CreateChallengeAsync"/>) and submit the
/// evidence for appraisal (<see cref="AttestAsync"/>).
/// </para>
/// <para>
/// This is ADDITIVE to the badge-tier (offline JWT verify) path provided by
/// <c>AddRootHeraldAuthentication</c>. The optional token returned by attest
/// with <see cref="AttestOptions.ReturnToken"/> is itself verifiable there.
/// </para>
/// Pure managed C# over <see cref="HttpClient"/>; no native dependencies.
/// </summary>
public sealed class RootHeraldBackgroundCheckClient
{
    /// <summary>Production Root Herald API base URL.</summary>
    public const string DefaultBaseUrl = "https://api.rootherald.io";

    private const string SecretKeyPrefix = "rh_sk_";

    private readonly HttpClient _http;
    private readonly bool _ownsHttp;

    /// <summary>
    /// Create a Background-Check client.
    /// </summary>
    /// <param name="secretKey">
    /// Your Root Herald secret key (<c>rh_sk_…</c>). Required. A publishable key
    /// (<c>rh_pk_…</c>) is rejected — it must never be used server-side.
    /// </param>
    /// <param name="baseUrl">API base URL. Defaults to the production API.</param>
    /// <param name="httpClient">
    /// Optional <see cref="HttpClient"/> (DI / IHttpClientFactory / tests). When
    /// supplied, the caller owns its lifetime; otherwise an internal one is used.
    /// </param>
    public RootHeraldBackgroundCheckClient(string secretKey, string? baseUrl = null, HttpClient? httpClient = null)
    {
        if (string.IsNullOrEmpty(secretKey))
            throw new ArgumentException("a secret key (rh_sk_…) is required", nameof(secretKey));
        if (!secretKey.StartsWith(SecretKeyPrefix, StringComparison.Ordinal))
            throw new ArgumentException(
                "secretKey must be a secret key (rh_sk_…); a publishable key (rh_pk_…) must never be used server-side",
                nameof(secretKey));

        _ownsHttp = httpClient is null;
        _http = httpClient ?? new HttpClient();
        _http.BaseAddress ??= new Uri((baseUrl ?? DefaultBaseUrl).TrimEnd('/') + "/");
        _http.DefaultRequestHeaders.Remove("Authorization");
        _http.DefaultRequestHeaders.Add("Authorization", $"Bearer {secretKey}");
    }

    /// <summary>
    /// <c>POST /api/v1/attestations/challenge</c> — mint a relay-friendly nonce.
    /// Relay <see cref="RootHeraldChallenge.Nonce"/> to the client; it quotes
    /// over it, then submit the resulting evidence with
    /// <see cref="AttestAsync"/> using
    /// <see cref="RootHeraldChallenge.ChallengeId"/>.
    /// </summary>
    /// <param name="deviceHint">Optional advisory hint identifying the device.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    public async Task<RootHeraldChallenge> CreateChallengeAsync(
        string? deviceHint = null, CancellationToken cancellationToken = default)
    {
        var body = new JsonObject();
        if (deviceHint is not null) body["deviceHint"] = deviceHint;

        var data = await PostAsync("api/v1/attestations/challenge", body, cancellationToken)
            .ConfigureAwait(false);
        var id = data["challengeId"]?.GetValue<string>();
        var nonce = data["nonce"]?.GetValue<string>();
        var expiresAt = data["expiresAt"]?.GetValue<string>();
        if (id is null || nonce is null || expiresAt is null)
            throw new RootHeraldApiException(200, "challenge response missing challengeId/nonce/expiresAt");
        return new RootHeraldChallenge(id, nonce, expiresAt);
    }

    /// <summary>
    /// <c>POST /api/v1/attestations/verify</c> — submit the opaque evidence blob
    /// for server-side appraisal and return the verdict (plus an optional signed
    /// EAT when <see cref="AttestOptions.ReturnToken"/> is set).
    /// <para>
    /// An un-enrolled / failing device is NOT an error — it returns a normal
    /// <see cref="AttestResult"/> carrying a <c>"deny"</c>/<c>"review"</c>
    /// verdict. Only protocol/auth/quota problems raise a
    /// <see cref="RootHeraldApiException"/>.
    /// </para>
    /// </summary>
    /// <param name="evidence">
    /// Opaque blob from the client collector, as a <see cref="JsonNode"/>; passed
    /// through verbatim.
    /// </param>
    /// <param name="options">Attest options carrying the challenge id and optional policy/returnToken.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    public async Task<AttestResult> AttestAsync(
        JsonNode evidence, AttestOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrEmpty(options.ChallengeId))
            throw new ArgumentException("AttestOptions.ChallengeId is required (from CreateChallengeAsync)", nameof(options));

        var body = new JsonObject
        {
            ["challengeId"] = options.ChallengeId,
            // evidence is opaque; embed verbatim (DeepClone detaches it from any parent).
            ["evidence"] = evidence.DeepClone(),
        };
        if (options.Policy is not null) body["policy"] = options.Policy;
        if (options.ReturnToken) body["returnToken"] = true;

        var data = await PostAsync("api/v1/attestations/verify", body, cancellationToken)
            .ConfigureAwait(false);
        var verdictNode = data["verdict"];
        if (verdictNode is not JsonObject)
            throw new RootHeraldApiException(200, "verify response missing verdict");

        var raw = verdictNode["verdict"]?.GetValue<string>();
        var token = data["token"]?.GetValue<string>();
        return new AttestResult
        {
            Verdict = Normalize(raw),
            VerdictData = verdictNode,
            Token = token,
        };
    }

    private async Task<JsonNode> PostAsync(string path, JsonNode body, CancellationToken cancellationToken)
    {
        using var response = await _http.PostAsJsonAsync(path, body, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            throw await ToApiExceptionAsync(response, cancellationToken).ConfigureAwait(false);

        var node = await response.Content.ReadFromJsonAsync<JsonNode>(cancellationToken).ConfigureAwait(false);
        if (node is null)
            throw new RootHeraldApiException((int)response.StatusCode, "empty Root Herald response");
        return node;
    }

    private static async Task<RootHeraldApiException> ToApiExceptionAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        string? errorCode = null;
        string? message = null;
        try
        {
            var node = await response.Content.ReadFromJsonAsync<JsonNode>(cancellationToken).ConfigureAwait(false);
            if (node is JsonObject obj)
            {
                errorCode = obj["error"]?.GetValue<string>();
                message = obj["message"]?.GetValue<string>() ?? obj["error_description"]?.GetValue<string>();
            }
        }
        catch (JsonException)
        {
            // non-JSON body — fall through to status-based mapping
        }

        var status = (int)response.StatusCode;
        return response.StatusCode switch
        {
            HttpStatusCode.Unauthorized => new InvalidSecretKeyException(message ?? "invalid secret key", errorCode),
            HttpStatusCode.UnprocessableEntity => new UnknownPolicyException(message ?? "unknown policy", errorCode),
            HttpStatusCode.Conflict => new ChallengeException(message ?? "challenge invalid or expired", errorCode),
            HttpStatusCode.BadRequest => new InvalidEvidenceException(message ?? "invalid evidence", errorCode),
            HttpStatusCode.TooManyRequests => new QuotaExceededException(message ?? "quota exceeded", errorCode),
            _ => new RootHeraldApiException(status, message ?? $"Root Herald API error (HTTP {status})", errorCode),
        };
    }

    /// <summary>
    /// Map the flat verdict the server emits ("pass"/"fail"/"warn") to the
    /// normalised SDK vocabulary. Unknown/missing values map to <c>"review"</c>
    /// (fail-closed: never silently <c>"allow"</c>).
    /// </summary>
    private static string Normalize(string? raw) => raw?.Trim().ToLowerInvariant() switch
    {
        "pass" or "allow" or "affirming" => "allow",
        "fail" or "deny" or "contraindicated" => "deny",
        _ => "review",
    };
}
