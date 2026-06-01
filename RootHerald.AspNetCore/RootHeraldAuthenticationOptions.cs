namespace RootHerald.AspNetCore;

/// <summary>
/// Configuration for <see cref="RootHeraldAuthenticationExtensions.AddRootHeraldAuthentication"/>.
///
/// All Root Herald deployments expose the standard OIDC discovery surface at
/// <c>{Issuer}/.well-known/openid-configuration</c>, which in turn declares the
/// JWKS URI used to verify token signatures. You give the SDK an issuer URL and
/// an audience (your Root Herald client_id); everything else is auto-discovered
/// and cached.
/// </summary>
public sealed class RootHeraldAuthenticationOptions
{
    /// <summary>
    /// The Root Herald issuer URL. For the hosted product this is
    /// <c>https://api.rootherald.io</c>. For custom-domain deployments it's
    /// <c>https://api.{your-domain}</c>. Required.
    /// </summary>
    public string Issuer { get; set; } = "";

    /// <summary>
    /// Your Root Herald client_id (sometimes called the relying-party id).
    /// Tokens are rejected unless their <c>aud</c> claim matches. Required.
    /// </summary>
    public string Audience { get; set; } = "";

    /// <summary>
    /// Clock skew tolerated when checking <c>exp</c> and <c>nbf</c>. Defaults
    /// to 30 seconds — same as the underlying JwtBearer handler default. Set
    /// to <c>TimeSpan.Zero</c> for strict enforcement (recommended in
    /// high-assurance flows).
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Authentication scheme name. Defaults to <c>"RootHerald"</c>. Change
    /// only if you need to register multiple JwtBearer handlers in the same
    /// app and need to disambiguate.
    /// </summary>
    public string Scheme { get; set; } = "RootHerald";

    /// <summary>
    /// When true (default), the configured Root Herald scheme is also
    /// registered as the application's default authentication scheme. Set to
    /// false if you have another scheme (e.g. cookies) that should win for
    /// non-API routes.
    /// </summary>
    public bool SetAsDefaultScheme { get; set; } = true;
}
