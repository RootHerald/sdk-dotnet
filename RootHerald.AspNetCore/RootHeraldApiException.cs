namespace RootHerald.AspNetCore;

/// <summary>
/// Thrown when the Root Herald API returns a non-2xx response during a
/// Background-Check (server → server) call. Subclasses map specific HTTP
/// statuses, mirroring the <c>@rootherald/node</c> taxonomy:
/// <list type="bullet">
///   <item><description>401 → <see cref="InvalidSecretKeyException"/></description></item>
///   <item><description>422 → <see cref="UnknownPolicyException"/></description></item>
///   <item><description>409 → <see cref="ChallengeException"/></description></item>
///   <item><description>400 → <see cref="InvalidEvidenceException"/></description></item>
///   <item><description>429 → <see cref="QuotaExceededException"/></description></item>
/// </list>
/// Note: an un-enrolled / failing device is NOT an error — it returns a normal
/// verdict. Only protocol/auth/quota problems raise one of these.
/// </summary>
public class RootHeraldApiException : Exception
{
    /// <summary>The HTTP status code returned by the Root Herald API.</summary>
    public int StatusCode { get; }

    /// <summary>The server-provided error code, when present.</summary>
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
