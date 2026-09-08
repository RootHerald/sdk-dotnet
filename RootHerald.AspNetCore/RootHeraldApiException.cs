namespace RootHerald.AspNetCore;

/// <summary>
/// Thrown when the Root Herald API returns a non-2xx response during a
/// Background-Check (server → server) call. Subclasses map specific HTTP
/// statuses, mirroring the <c>@rootherald/node</c> taxonomy:
/// <list type="bullet">
///   <item><description>401 → <see cref="InvalidSecretKeyException"/></description></item>
///   <item><description>422 → <see cref="UnknownPolicyException"/></description></item>
///   <item><description>422 <c>policy_downgrade</c> → <see cref="PolicyDowngradeException"/></description></item>
///   <item><description>422 <c>admission_refused</c> → <see cref="AdmissionRefusedException"/></description></item>
///   <item><description>409 → <see cref="ChallengeException"/></description></item>
///   <item><description>400 → <see cref="InvalidEvidenceException"/></description></item>
///   <item><description>429 → <see cref="QuotaExceededException"/></description></item>
/// </list>
/// A 422 is told apart by the server's error code (<see cref="ErrorCode"/>);
/// one without a recognised code is <see cref="UnknownPolicyException"/>.
/// Note: an un-enrolled / failing device is NOT an error — it returns a normal
/// verdict. Only protocol/auth/quota problems raise one of these.
/// </summary>
public class RootHeraldApiException : Exception
{
    /// <summary>The HTTP status code returned by the Root Herald API.</summary>
    public int StatusCode { get; }

    /// <summary>
    /// The server-provided error code, when present — the <c>error</c> field of
    /// the response body, e.g. <c>policy_downgrade</c> or <c>admission_refused</c>.
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

/// <summary>The secret key was rejected by the Root Herald API (HTTP 401).</summary>
public sealed class InvalidSecretKeyException : RootHeraldApiException
{
    /// <summary>Create the exception.</summary>
    public InvalidSecretKeyException(string message, string? errorCode = null)
        : base(401, message, errorCode) { }
}

/// <summary>The named policy is unknown or not owned by this tenant (HTTP 422).</summary>
public sealed class UnknownPolicyException : RootHeraldApiException
{
    /// <summary>Create the exception.</summary>
    public UnknownPolicyException(string message, string? errorCode = null)
        : base(422, message, errorCode) { }
}

/// <summary>
/// The verify call named a policy weaker than the one the challenge was issued
/// with (HTTP 422, error code <c>policy_downgrade</c>).
/// </summary>
public sealed class PolicyDowngradeException : RootHeraldApiException
{
    /// <summary>Create the exception.</summary>
    public PolicyDowngradeException(string message, string? errorCode = null)
        : base(422, message, errorCode) { }
}

/// <summary>
/// Enrollment was refused because the device's TPM class can never satisfy the
/// challenge's policy (HTTP 422, error code <c>admission_refused</c>). The
/// class is in <see cref="Exception.Message"/>.
/// </summary>
public sealed class AdmissionRefusedException : RootHeraldApiException
{
    /// <summary>Create the exception.</summary>
    public AdmissionRefusedException(string message, string? errorCode = null)
        : base(422, message, errorCode) { }
}

/// <summary>The challenge is unknown, expired, or already consumed (HTTP 409).</summary>
public sealed class ChallengeException : RootHeraldApiException
{
    /// <summary>Create the exception.</summary>
    public ChallengeException(string message, string? errorCode = null)
        : base(409, message, errorCode) { }
}

/// <summary>
/// The submitted evidence blob was malformed or unparseable (HTTP 400). An
/// un-enrolled / failing device is NOT this exception — that returns a verdict.
/// </summary>
public sealed class InvalidEvidenceException : RootHeraldApiException
{
    /// <summary>Create the exception.</summary>
    public InvalidEvidenceException(string message, string? errorCode = null)
        : base(400, message, errorCode) { }
}

/// <summary>The account's attestation quota or rate limit was exceeded (HTTP 429).</summary>
public sealed class QuotaExceededException : RootHeraldApiException
{
    /// <summary>Create the exception.</summary>
    public QuotaExceededException(string message, string? errorCode = null)
        : base(429, message, errorCode) { }
}
