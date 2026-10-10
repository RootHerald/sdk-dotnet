namespace RootHerald.AspNetCore;

/// <summary>
/// Thrown when the Root Herald API returns a non-2xx response during a
/// Background-Check (server → server) call, or a 2xx body the SDK refuses.
/// Subclasses map specific HTTP statuses, mirroring the
/// <c>@rootherald/node</c> taxonomy:
/// <list type="bullet">
///   <item><description>401 <c>activation_refused</c> → <see cref="ActivationRefusedException"/></description></item>
///   <item><description>401, any other code → <see cref="InvalidSecretKeyException"/></description></item>
///   <item><description>422 <c>unknown_policy</c> (or no code) → <see cref="UnknownPolicyException"/></description></item>
///   <item><description>422 <c>admission_refused</c> → <see cref="AdmissionRefusedException"/></description></item>
///   <item><description>409 <c>key_rotation_conflict</c> → this base type</description></item>
///   <item><description>409, any other → <see cref="ChallengeException"/></description></item>
///   <item><description>400 <c>invalid_ask</c> → <see cref="InvalidAskException"/></description></item>
///   <item><description>400, any other (including <c>wire_version_unsupported</c>, <c>invalid_enroll_shape</c>) → <see cref="InvalidEvidenceException"/></description></item>
///   <item><description>429 <c>budget_exhausted</c>, or an <c>X-RootHerald-Quota</c> header → <see cref="QuotaExceededException"/></description></item>
///   <item><description>429, any other → <see cref="RateLimitedException"/></description></item>
///   <item><description>200 whose verdict does not echo the binding the challenge named → <see cref="ExpectedNotEnforcedException"/></description></item>
/// </list>
/// Where one status carries two refusals the server's error code
/// (<see cref="ErrorCode"/>) or a header tells them apart. A status or code no
/// subclass covers — including 422 <c>posture_not_bound</c>,
/// <c>expected_unknown</c> and <c>key_disclosure_too_low</c>, and 402
/// <c>plan_lapsed</c> — is this base type with <see cref="ErrorCode"/> preserved.
/// Note: an un-enrolled / failing device is NOT an error — it returns a normal
/// verdict. Only protocol/auth/budget problems raise one of these.
/// </summary>
public class RootHeraldApiException : Exception
{
    /// <summary>The HTTP status code returned by the Root Herald API.</summary>
    public int StatusCode { get; }

    /// <summary>
    /// The server-provided error code, when present — the <c>error</c> field of
    /// the response body, e.g. <c>unknown_policy</c> or <c>admission_refused</c>.
    /// </summary>
    public string? ErrorCode { get; }

    /// <summary>Create an API exception for the given status.</summary>
    public RootHeraldApiException(int statusCode, string message, string? errorCode = null)
        : base(message)
    {
        StatusCode = statusCode;
        ErrorCode = errorCode;
    }
}

/// <summary>
/// The secret key was rejected by the Root Herald API (HTTP 401). A 401
/// carrying <c>activation_refused</c> is <see cref="ActivationRefusedException"/>
/// instead.
/// </summary>
public sealed class InvalidSecretKeyException : RootHeraldApiException
{
    /// <summary>Create the exception.</summary>
    public InvalidSecretKeyException(string message, string? errorCode = null)
        : base(401, message, errorCode) { }
}

/// <summary>
/// <c>POST /api/v1/attest/activate</c> refused the enrollment (HTTP 401, error
/// code <c>activation_refused</c>): the <c>enrollmentId</c> is unknown, spent
/// or foreign, or the proof did not match. The secret key was accepted; this
/// is not a credential problem. Every activation refusal reason produces this
/// one answer.
/// </summary>
public sealed class ActivationRefusedException : RootHeraldApiException
{
    /// <summary>Create the exception.</summary>
    public ActivationRefusedException(string message, string? errorCode = null)
        : base(401, message, errorCode) { }
}

/// <summary>
/// A policy bound to the API key no longer exists; nothing is substituted
/// (HTTP 422, error code <c>unknown_policy</c>). Rebind the key from the
/// dashboard or <c>PUT /api/v1/admin/api-keys/{id}/policies</c>.
/// </summary>
public sealed class UnknownPolicyException : RootHeraldApiException
{
    /// <summary>Create the exception.</summary>
    public UnknownPolicyException(string message, string? errorCode = null)
        : base(422, message, errorCode) { }
}

/// <summary>
/// Enrollment was refused because the device's TPM class can never satisfy the
/// identity policy bound to the API key (HTTP 422, error code
/// <c>admission_refused</c>). The class is in <see cref="Exception.Message"/>.
/// </summary>
public sealed class AdmissionRefusedException : RootHeraldApiException
{
    /// <summary>Create the exception.</summary>
    public AdmissionRefusedException(string message, string? errorCode = null)
        : base(422, message, errorCode) { }
}

/// <summary>
/// The challenge is unknown, expired, or already consumed (HTTP 409). A 409
/// carrying <c>key_rotation_conflict</c> is a plain
/// <see cref="RootHeraldApiException"/> instead: the key challenge was fine,
/// the rotation it asked for collided with another.
/// </summary>
public sealed class ChallengeException : RootHeraldApiException
{
    /// <summary>Create the exception.</summary>
    public ChallengeException(string message, string? errorCode = null)
        : base(409, message, errorCode) { }
}

/// <summary>
/// The relayed blob was malformed or could not be appraised (HTTP 400). This
/// includes <c>wire_version_unsupported</c> (a 7.0-shaped enroll body) and
/// <c>invalid_enroll_shape</c> (an attestation key whose qualified name does
/// not follow from its parent). An un-enrolled / failing device is NOT this
/// exception — that returns a verdict. A 400 carrying <c>invalid_ask</c> is
/// <see cref="InvalidAskException"/>.
/// </summary>
public sealed class InvalidEvidenceException : RootHeraldApiException
{
    /// <summary>Create the exception.</summary>
    public InvalidEvidenceException(string message, string? errorCode = null)
        : base(400, message, errorCode) { }
}

/// <summary>
/// The challenge named an ask the server does not know, such as the retired
/// <c>"key"</c> (HTTP 400, error code <c>invalid_ask</c>). The backend's code
/// is wrong, not the device: keys are minted with
/// <see cref="RootHeraldClient.IssueKeyChallengeAsync"/>.
/// </summary>
public sealed class InvalidAskException : RootHeraldApiException
{
    /// <summary>Create the exception.</summary>
    public InvalidAskException(string message, string? errorCode = null)
        : base(400, message, errorCode) { }
}

/// <summary>The budget that refused a device, as the server names it.</summary>
/// <param name="Id">The budget's id.</param>
/// <param name="Name">The budget's display name.</param>
public sealed record RefusingBudget(string Id, string Name);

/// <summary>
/// The API key's budget cannot pay for a device new to the period (HTTP 429
/// with error code <c>budget_exhausted</c> or an <c>X-RootHerald-Quota</c>
/// header). <see cref="Budget"/> names it when the server did. A 429 without
/// that signal is <see cref="RateLimitedException"/>.
/// </summary>
public sealed class QuotaExceededException : RootHeraldApiException
{
    /// <summary>The budget that refused, when the server named it.</summary>
    public RefusingBudget? Budget { get; }

    /// <summary>Create the exception.</summary>
    public QuotaExceededException(string message, string? errorCode = null, RefusingBudget? budget = null)
        : base(429, message, errorCode)
    {
        Budget = budget;
    }
}

/// <summary>
/// The request-rate limiter refused the call (HTTP 429 without a budget
/// signal). Retry after <see cref="RetryAfterSeconds"/>. Distinct from
/// <see cref="QuotaExceededException"/>, the budget ceiling.
/// </summary>
public sealed class RateLimitedException : RootHeraldApiException
{
    /// <summary>
    /// Seconds to wait before retrying: the <c>Retry-After</c> header, else the
    /// body's <c>retryAfterSeconds</c>, else null.
    /// </summary>
    public int? RetryAfterSeconds { get; }

    /// <summary>Create the exception.</summary>
    public RateLimitedException(string message, string? errorCode = null, int? retryAfterSeconds = null)
        : base(429, message, errorCode)
    {
        RetryAfterSeconds = retryAfterSeconds;
    }
}

/// <summary>
/// The verify response did not echo the <c>ExpectedKey</c> /
/// <c>ExpectedDevices</c> the challenge named, so the binding was not
/// enforced. The API ignores unknown JSON fields, so a server that predates
/// the binding would accept any device and answer a verdict with no
/// <c>expected</c> block; this refusal turns that silence into an error. Do
/// not trust the verdict.
/// </summary>
public sealed class ExpectedNotEnforcedException : RootHeraldApiException
{
    /// <summary>Create the exception.</summary>
    public ExpectedNotEnforcedException(string message)
        : base(200, message) { }
}
