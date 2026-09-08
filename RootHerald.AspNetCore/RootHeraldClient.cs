using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace RootHerald.AspNetCore;

/// <summary>
/// A challenge minted by
/// <see cref="RootHeraldClient.IssueChallengeAsync(ChallengeOptions?, CancellationToken)"/>.
/// Relay <see cref="Challenge"/> to the dumb client verbatim; it parses the
/// nonce and the ask from it, quotes over the nonce, and returns an opaque
/// evidence blob, which the server submits to
/// <see cref="RootHeraldClient.VerifyAsync"/> using <see cref="ChallengeId"/>.
/// </summary>
/// <param name="ChallengeId">Opaque single-use id; pass it back to VerifyAsync.</param>
/// <param name="Nonce">The base64 nonce the client quotes over, also carried inside <paramref name="Challenge"/>.</param>
/// <param name="ExpiresAt">ISO 8601 timestamp after which the challenge is no longer valid.</param>
/// <param name="Challenge">
/// The string to relay to the client: <c>rhc1.&lt;base64url nonce&gt;.&lt;base64url ask-json&gt;</c>.
/// Null when the server predates the ask model; relay <paramref name="Nonce"/> then.
/// </param>
public sealed record RootHeraldChallenge(string ChallengeId, string Nonce, string ExpiresAt, string? Challenge = null);

/// <summary>What a challenge asks the device to produce.</summary>
public static class Ask
{
    /// <summary>Proof the evidence comes from the enrolled TPM.</summary>
    public const string Identity = "identity";

    /// <summary>The measured-boot event log alongside the quote.</summary>
    public const string Posture = "posture";

    /// <summary>
    /// A TPM-resident signing key, created for this challenge and certified by
    /// the device's attestation key. The verdict then carries its public half as
    /// <see cref="AttestResult.Key"/>.
    /// </summary>
    public const string Key = "key";
}

/// <summary>
/// Options for <see cref="RootHeraldClient.IssueChallengeAsync(ChallengeOptions?, CancellationToken)"/>.
/// The default asks for identity and posture.
/// </summary>
public sealed record ChallengeOptions
{
    /// <summary>
    /// What the device must produce, from the <see cref="Ask"/> constants. Null
    /// or empty means identity + posture.
    /// </summary>
    public IReadOnlyList<string>? Ask { get; init; }

    /// <summary>
    /// Pins the policy this challenge will be appraised under. A later
    /// <see cref="RootHeraldClient.VerifyAsync"/> may name the same policy or
    /// none; naming a weaker one fails with <see cref="PolicyDowngradeException"/>.
    /// </summary>
    public string? Policy { get; init; }

    /// <summary>
    /// What a certified key will be used for. Read only when <see cref="Ask"/>
    /// contains <see cref="AspNetCore.Ask.Key"/>; <c>"sign"</c> is the only purpose today.
    /// </summary>
    public string? KeyPurpose { get; init; }

    /// <summary>Optional advisory hint identifying the device.</summary>
    public string? DeviceHint { get; init; }
}

/// <summary>
/// Options for <see cref="RootHeraldClient.VerifyAsync"/>.
/// </summary>
public sealed record AttestOptions
{
    /// <summary>The single-use challenge id from IssueChallengeAsync. Required.</summary>
    public required string ChallengeId { get; init; }

    /// <summary>
    /// Caller-named policy: a tenant-owned policy id/name or a
    /// <c>rootherald:builtin:*</c> name. Unknown/foreign names fail closed (422).
    /// When the challenge pinned a policy, naming a weaker one here is refused
    /// with <see cref="PolicyDowngradeException"/>.
    /// </summary>
    public string? Policy { get; init; }

    /// <summary>
    /// Optional requested disclosure class for the returned device claim —
    /// <c>"verdict"</c>, <c>"pseudonymous"</c>, <c>"derived"</c>, or
    /// <c>"full"</c>. Sent on the wire as <c>requestedDisclosureClass</c>;
    /// omitted from the request when null.
    /// </summary>
    public string? RequestedDisclosureClass { get; init; }
}

/// <summary>
/// A TPM-resident signing key the appraisal certified, returned when the
/// challenge asked for <see cref="Ask.Key"/> and the verdict passed. Store
/// <see cref="Jwk"/> against the user; a later request the device signed is
/// checked locally with <see cref="RootHeraldClient.VerifyKeySignature"/>, with
/// no call to Root Herald.
/// <para>
/// <see cref="KeyId"/> identifies the key, not the device, and a fresh key is
/// certified per ask.
/// </para>
/// </summary>
/// <param name="KeyId">Root Herald's id for this key, stable for the key's lifetime.</param>
/// <param name="Jwk">The public key as a JWK: <c>{ kty: "EC", crv: "P-256" | "P-384", x, y }</c>.</param>
/// <param name="Purpose">What the key is certified for; echoes the challenge's <c>keyPurpose</c>.</param>
/// <param name="AuthPolicy">base64 <c>authPolicy</c> digest from the key's public area, when it has one.</param>
/// <param name="CertifiedAt">When the certification was appraised.</param>
public sealed record CertifiedKey(
    string KeyId,
    JsonObject Jwk,
    string Purpose,
    string? AuthPolicy,
    DateTimeOffset CertifiedAt);

/// <summary>
/// The result of <see cref="RootHeraldClient.VerifyAsync"/>: the
/// normalised verdict and the full verdict node.
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

    /// <summary>
    /// Assurance-claim URNs the device satisfied, from the top-level
    /// <c>assuranceClaimsMet</c> sibling of <c>verdict</c> on the wire. Empty
    /// when the server omits it.
    /// </summary>
    public IReadOnlyList<string> AssuranceClaimsMet { get; init; } = Array.Empty<string>();

    /// <summary>
    /// The attest-first / enroll-on-miss signal, from the top-level
    /// <c>enrollmentRequired</c> sibling of <c>verdict</c>. <c>true</c> when the
    /// device must (re-)enroll before it can be appraised.
    /// </summary>
    public bool EnrollmentRequired { get; init; }

    /// <summary>
    /// The signing key the appraisal certified, from the top-level <c>key</c>
    /// sibling of <c>verdict</c>. Present only when the challenge asked for
    /// <see cref="Ask.Key"/> and the verdict passed; null otherwise, whatever the
    /// evidence carried.
    /// </summary>
    public CertifiedKey? Key { get; init; }

    /// <summary>True when the verdict is <c>"allow"</c>.</summary>
    public bool IsAllowed => string.Equals(Verdict, "allow", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The device identifier, <c>verdict.device.ueid</c>. Null when the
    /// disclosure class withheld it; fail closed on null if you key a decision
    /// on it.
    /// </summary>
    public string? DeviceId => VerdictData["device"]?["ueid"]?.GetValue<string>();
}

/// <summary>
/// Server → server Background-Check client.
/// <para>
/// The customer's dumb client collects an opaque evidence blob (no keys, no
/// Root Herald contact) and hands it to the customer's own server. The server
/// uses this client, authenticated with its <c>rh_sk_</c> secret key, to mint a
/// challenge (<see cref="IssueChallengeAsync(ChallengeOptions?, CancellationToken)"/>)
/// and submit the evidence for appraisal (<see cref="VerifyAsync"/>).
/// </para>
/// Pure managed C# over <see cref="HttpClient"/>; no native dependencies.
/// </summary>
public sealed class RootHeraldClient
{
    /// <summary>Production Root Herald API base URL.</summary>
    public const string DefaultBaseUrl = "https://rootherald.io";

    private const string SecretKeyPrefix = "rh_sk_";

    // Server error codes that refine a 422 beyond "unknown policy".
    private const string CodePolicyDowngrade = "policy_downgrade";
    private const string CodeAdmissionRefused = "admission_refused";

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
    /// supplied, the caller owns its lifetime; otherwise an internal one is used.
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
            // MED-19: no SDK checked this. A typo'd or http:// base URL sends the
            // full-privilege rh_sk_ secret in cleartext. Localhost is exempt so the
            // local docker stack still works.
            if (baseUri is null || !baseUri.IsLoopback)
                throw new ArgumentException(
                    $"baseUrl must be an absolute https URL (got '{resolvedBase}').",
                    nameof(baseUrl));
        }

        _ownsHttp = httpClient is null;
        _http = httpClient ?? new HttpClient();
        _baseUri = baseUri!;
        _secretKey = secretKey;

        // MED-20: auth is attached PER REQUEST, not onto the client.
        //
        // This used to set _http.DefaultRequestHeaders["Authorization"] and
        // _http.BaseAddress on a caller-supplied HttpClient. With
        // IHttpClientFactory or a typed/singleton client — the documented way to
        // inject one — that client is shared, so the rh_sk_ secret was attached to
        // EVERY request it made, including to third-party hosts. The `??=` on
        // BaseAddress had the same shape of bug: an injected client's existing
        // BaseAddress silently won, sending the key and the evidence somewhere else
        // entirely. Mutating an object you do not own is the defect; scoping the
        // header to our own requests fixes both.
    }

    /// <summary>
    /// <c>POST /api/v1/attest/challenge</c> — mint a challenge asking for
    /// identity and posture. Relay <see cref="RootHeraldChallenge.Challenge"/>
    /// to the client; it quotes over the nonce inside it, then submit the
    /// resulting evidence with <see cref="VerifyAsync"/> using
    /// <see cref="RootHeraldChallenge.ChallengeId"/>.
    /// </summary>
    /// <param name="deviceHint">Optional advisory hint identifying the device.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    public Task<RootHeraldChallenge> IssueChallengeAsync(
        string? deviceHint = null, CancellationToken cancellationToken = default)
        => IssueChallengeAsync(new ChallengeOptions { DeviceHint = deviceHint }, cancellationToken);

    /// <summary>
    /// <c>POST /api/v1/attest/challenge</c> — mint a challenge carrying the
    /// given ask. Relay <see cref="RootHeraldChallenge.Challenge"/> to the
    /// client verbatim; it parses the ask from it and produces matching
    /// evidence, which the server submits with <see cref="VerifyAsync"/> using
    /// <see cref="RootHeraldChallenge.ChallengeId"/>.
    /// </summary>
    /// <param name="options">The ask, pinned policy, key purpose and device hint. Null asks for identity + posture.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    public async Task<RootHeraldChallenge> IssueChallengeAsync(
        ChallengeOptions? options, CancellationToken cancellationToken = default)
    {
        var body = new JsonObject();
        if (options?.DeviceHint is { } hint) body["deviceHint"] = hint;
        if (options?.Ask is { Count: > 0 } ask)
            body["ask"] = new JsonArray(ask.Select(a => (JsonNode?)JsonValue.Create(a)).ToArray());
        if (options?.Policy is { } policy) body["policy"] = policy;
        if (options?.KeyPurpose is { } purpose) body["keyPurpose"] = purpose;

        var data = await PostAsync("api/v1/attest/challenge", body, cancellationToken)
            .ConfigureAwait(false);
        var id = data["challengeId"]?.GetValue<string>();
        var nonce = data["nonce"]?.GetValue<string>();
        var expiresAt = data["expiresAt"]?.GetValue<string>();
        if (id is null || nonce is null || expiresAt is null)
            throw new RootHeraldApiException(200, "challenge response missing challengeId/nonce/expiresAt");
        return new RootHeraldChallenge(id, nonce, expiresAt, data["challenge"]?.GetValue<string>());
    }

    /// <summary>
    /// <c>POST /api/v1/attest/verify</c> — submit the opaque evidence blob
    /// for server-side appraisal and return the verdict.
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
    /// <param name="options">Attest options carrying the challenge id and optional policy.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    public async Task<AttestResult> VerifyAsync(
        JsonNode evidence, AttestOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrEmpty(options.ChallengeId))
            throw new ArgumentException("AttestOptions.ChallengeId is required (from IssueChallengeAsync)", nameof(options));

        var body = new JsonObject
        {
            ["challengeId"] = options.ChallengeId,
            // evidence is opaque; embed verbatim (DeepClone detaches it from any parent).
            ["evidence"] = evidence.DeepClone(),
        };
        if (options.Policy is not null) body["policy"] = options.Policy;
        if (options.RequestedDisclosureClass is not null)
            body["requestedDisclosureClass"] = options.RequestedDisclosureClass;

        var data = await PostAsync("api/v1/attest/verify", body, cancellationToken)
            .ConfigureAwait(false);
        var verdictNode = data["verdict"];
        if (verdictNode is not JsonObject)
            throw new RootHeraldApiException(200, "verify response missing verdict");

        // The pass/fail token and per-device appraisal fields (earStatus,
        // attestationType, quoteVerified, …) live under verdict.device.
        var raw = verdictNode["device"]?["verdict"]?.GetValue<string>();
        var verdict = Normalize(raw);

        // The contract certifies nothing on a failing verdict; do not let a stray
        // key on the wire outlive the verdict it came with.
        var key = verdict == "allow" ? ReadCertifiedKey(data["key"]) : null;

        return new AttestResult
        {
            Verdict = verdict,
            VerdictData = verdictNode,
            AssuranceClaimsMet = ReadStringArray(data["assuranceClaimsMet"]),
            EnrollmentRequired = data["enrollmentRequired"]?.GetValue<bool>() ?? false,
            Key = key,
        };
    }

    /// <summary>
    /// Enroll relay — leg 1. <c>POST /api/v1/attest/enroll</c>.
    /// <para>
    /// Relays the client's <c>EnrollBegin()</c> blob to Root Herald with the
    /// <c>rh_sk_</c> secret and returns the
    /// <see cref="RelayEnrollResult.Challenge"/> to hand to the client's
    /// <c>EnrollComplete</c>, whose result goes to
    /// <see cref="RelayActivateAsync"/>.
    /// </para>
    /// <para>
    /// With <paramref name="challengeId"/> the request goes to
    /// <c>?challengeId=</c> and admission runs against the policy stored on
    /// that challenge instead of the tenant default, so a device whose TPM
    /// class can never satisfy it is refused before it gets an attestation key:
    /// <see cref="AdmissionRefusedException"/>, with the class in the message.
    /// </para>
    /// <para>
    /// The client never holds the <c>rh_sk_</c> key and never talks to Root
    /// Herald; this backend helper is the only thing that does.
    /// </para>
    /// </summary>
    /// <param name="enrollRequestBlob">The opaque enroll-begin blob from the client.</param>
    /// <param name="challengeId">A live challenge id from IssueChallengeAsync, or null for the tenant default policy.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    public async Task<RelayEnrollResult> RelayEnrollAsync(
        EnrollRequestBlob enrollRequestBlob, string? challengeId = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(enrollRequestBlob);
        if (string.IsNullOrEmpty(enrollRequestBlob.EkPublicKey) ||
            string.IsNullOrEmpty(enrollRequestBlob.AkPublicArea))
            throw new ArgumentException(
                "enroll request blob requires ekPublicKey and akPublicArea", nameof(enrollRequestBlob));

        var path = "api/v1/attest/enroll";
        if (!string.IsNullOrEmpty(challengeId))
            path += "?challengeId=" + Uri.EscapeDataString(challengeId);

        using var response = await RawPostAsync(path, enrollRequestBlob, cancellationToken)
            .ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
            throw await ToApiExceptionAsync(response, cancellationToken).ConfigureAwait(false);

        var challenge = await response.Content
            .ReadFromJsonAsync<EnrollActivationChallenge>(cancellationToken).ConfigureAwait(false);
        if (challenge is null ||
            string.IsNullOrEmpty(challenge.DeviceId) ||
            string.IsNullOrEmpty(challenge.CredentialBlob) ||
            string.IsNullOrEmpty(challenge.EncryptedSecret))
            throw new RootHeraldApiException(
                (int)response.StatusCode,
                "enroll response missing deviceId/credentialBlob/encryptedSecret");

        return new RelayEnrollResult
        {
            DeviceId = challenge.DeviceId,
            Challenge = challenge,
        };
    }

    /// <summary>
    /// Enroll relay — leg 2. <c>POST /api/v1/attest/activate</c>.
    /// <para>
    /// Relays the client's <c>EnrollComplete()</c> blob (the decrypted credential
    /// secret) to Root Herald, completing the EK→AK credential-activation
    /// handshake. Every <see cref="RelayEnrollAsync"/> leads here: enrollment
    /// always issues a challenge, including for a known device, because
    /// re-enrollment is how a device rotates its attestation key.
    /// </para>
    /// Returns the terminal <c>{ deviceId, status, enrolledAt }</c> body;
    /// <see cref="RelayActivateResponse.DeviceId"/> is the load-bearing field the
    /// backend maps to its user.
    /// </summary>
    /// <param name="activationResponse">The opaque enroll-complete blob from the client.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    public async Task<RelayActivateResponse> RelayActivateAsync(
        EnrollActivationResponse activationResponse, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(activationResponse);
        if (string.IsNullOrEmpty(activationResponse.DeviceId) ||
            string.IsNullOrEmpty(activationResponse.DecryptedSecret))
            throw new ArgumentException(
                "activation response requires deviceId and decryptedSecret", nameof(activationResponse));

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
    /// no call to Root Herald. The customer stores the JWK at attestation time
    /// and checks each later request locally.
    /// <para>
    /// The signature is ECDSA over SHA-256(message) for P-256 and
    /// SHA-384(message) for P-384, in either the raw <c>r||s</c> form (64 or 96
    /// bytes, as a TPM emits) or ASN.1 DER. Returns false for anything it cannot
    /// verify — an unsupported key, a point off the curve, or a malformed
    /// signature — and never throws.
    /// </para>
    /// </summary>
    public static bool VerifyKeySignature(JsonObject jwk, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (jwk is null) return false;
        try
        {
            if (jwk["kty"]?.GetValue<string>() != "EC") return false;
            var (curve, hash, size) = jwk["crv"]?.GetValue<string>() switch
            {
                "P-256" => (ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256, 32),
                "P-384" => (ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384, 48),
                _ => (default(ECCurve), default(HashAlgorithmName), 0),
            };
            if (size == 0) return false;

            var x = DecodeCoordinate(jwk["x"]?.GetValue<string>(), size);
            var y = DecodeCoordinate(jwk["y"]?.GetValue<string>(), size);
            if (x is null || y is null) return false;

            // ECDsa.Create validates the point is on the curve and throws otherwise.
            using var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = curve,
                Q = new ECPoint { X = x, Y = y },
            });

            if (signature.Length == 2 * size &&
                ecdsa.VerifyData(message, signature, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                return true;
            return ecdsa.VerifyData(message, signature, hash, DSASignatureFormat.Rfc3279DerSequence);
        }
        catch (Exception)
        {
            // A malformed key or signature is a false, not a fault.
            return false;
        }
    }

    /// <summary>
    /// Decodes one base64url JWK coordinate of exactly <paramref name="size"/>
    /// bytes. JWK coordinates are unpadded, but padding is tolerated.
    /// </summary>
    private static byte[]? DecodeCoordinate(string? value, int size)
    {
        if (string.IsNullOrEmpty(value)) return null;
        var s = value.TrimEnd('=').Replace('-', '+').Replace('_', '/');
        s = s.PadRight(s.Length + (4 - s.Length % 4) % 4, '=');
        try
        {
            var bytes = Convert.FromBase64String(s);
            return bytes.Length == size ? bytes : null;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// <summary>
    /// Reads the top-level <c>key</c> of a verify response. Absent is null; a
    /// key without its load-bearing fields is a malformed response, not a null
    /// the caller might misread as "no key asked".
    /// </summary>
    private static CertifiedKey? ReadCertifiedKey(JsonNode? node)
    {
        if (node is null) return null;
        if (node is not JsonObject obj)
            throw new RootHeraldApiException(200, "verify response key is not an object");

        var keyId = obj["keyId"]?.GetValue<string>();
        var jwk = obj["jwk"] as JsonObject;
        var purpose = obj["purpose"]?.GetValue<string>();
        var certifiedAtRaw = obj["certifiedAt"]?.GetValue<string>();
        if (string.IsNullOrEmpty(keyId) || jwk is null ||
            string.IsNullOrEmpty(jwk["kty"]?.GetValue<string>()) ||
            string.IsNullOrEmpty(jwk["x"]?.GetValue<string>()) ||
            string.IsNullOrEmpty(jwk["y"]?.GetValue<string>()) ||
            !DateTimeOffset.TryParse(certifiedAtRaw, null, System.Globalization.DateTimeStyles.RoundtripKind, out var certifiedAt))
            throw new RootHeraldApiException(200, "verify response key missing keyId/jwk/certifiedAt");

        return new CertifiedKey(
            keyId,
            (JsonObject)jwk.DeepClone(),
            purpose ?? "sign",
            obj["authPolicy"]?.GetValue<string>(),
            certifiedAt);
    }

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
            // A 422 is told apart by the server's error code; one without a
            // recognised code is the policy being unknown.
            HttpStatusCode.UnprocessableEntity when errorCode == CodePolicyDowngrade =>
                new PolicyDowngradeException(message ?? "policy weaker than the challenge's", errorCode),
            HttpStatusCode.UnprocessableEntity when errorCode == CodeAdmissionRefused =>
                new AdmissionRefusedException(message ?? "enrollment refused for this device class", errorCode),
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

    /// <summary>Reads a JSON string array, tolerating a null/absent/non-array node.</summary>
    private static IReadOnlyList<string> ReadStringArray(JsonNode? node)
    {
        if (node is not JsonArray array)
            return Array.Empty<string>();

        var values = new List<string>(array.Count);
        foreach (var item in array)
        {
            if (item?.GetValue<string>() is { } value)
                values.Add(value);
        }
        return values;
    }
}
