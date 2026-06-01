using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace RootHerald.AspNetCore;

/// <summary>
/// DI + middleware extensions for Root Herald attestation.
/// </summary>
public static class RootHeraldAuthenticationExtensions
{
    private const string DeviceClaimType = "rootherald_device";
    private const string VerdictItemKey = "__RootHerald_Verdict";

    /// <summary>
    /// Registers Root Herald JWT bearer authentication. Verifies tokens
    /// signed by the JWKS at <c>{Issuer}/.well-known/jwks.json</c>; uses
    /// OIDC discovery for key rotation; populates a strongly-typed
    /// <see cref="RootHeraldVerdict"/> on HttpContext after successful auth.
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services.AddRootHeraldAuthentication(options =>
    /// {
    ///     options.Issuer = "https://api.rootherald.io";
    ///     options.Audience = "plat_my_client_id";
    /// });
    /// </code>
    /// </example>
    public static AuthenticationBuilder AddRootHeraldAuthentication(
        this IServiceCollection services,
        Action<RootHeraldAuthenticationOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);

        var options = new RootHeraldAuthenticationOptions();
        configure(options);

        if (string.IsNullOrWhiteSpace(options.Issuer))
            throw new ArgumentException(
                "RootHeraldAuthenticationOptions.Issuer is required.", nameof(configure));
        if (string.IsNullOrWhiteSpace(options.Audience))
            throw new ArgumentException(
                "RootHeraldAuthenticationOptions.Audience is required.", nameof(configure));

        // Normalise issuer (no trailing slash) so JwtBearer matches the iss claim.
        var issuer = options.Issuer.TrimEnd('/');

        var authBuilder = options.SetAsDefaultScheme
            ? services.AddAuthentication(options.Scheme)
            : services.AddAuthentication();

        authBuilder.AddJwtBearer(options.Scheme, jwt =>
        {
            // OIDC discovery handles JWKS fetch + key rotation + cache (1h default).
            jwt.Authority = issuer;
            jwt.RequireHttpsMetadata = !issuer.StartsWith("http://localhost", StringComparison.OrdinalIgnoreCase);

            // Keep JWT claim names verbatim ("sub", "acr", "amr", "rootherald_device").
            // Without this, ASP.NET rewrites them to legacy XML-namespace URLs and
            // our typed lookups would all return null.
            jwt.MapInboundClaims = false;

            jwt.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = issuer,
                ValidateAudience = true,
                ValidAudience = options.Audience,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                RequireSignedTokens = true,
                RequireExpirationTime = true,
                ClockSkew = options.ClockSkew,
                NameClaimType = "sub",
            };

            jwt.Events = new JwtBearerEvents
            {
                OnTokenValidated = ctx =>
                {
                    if (ctx.Principal is null || ctx.HttpContext is null)
                        return Task.CompletedTask;
                    var verdict = BuildVerdict(ctx.Principal, issuer);
                    if (verdict is not null)
                        ctx.HttpContext.Items[VerdictItemKey] = verdict;
                    return Task.CompletedTask;
                },
            };
        });

        return authBuilder;
    }

    /// <summary>
    /// Returns the strongly-typed <see cref="RootHeraldVerdict"/> for the
    /// current request, or <c>null</c> if no Root Herald token was validated.
    /// </summary>
    public static RootHeraldVerdict? GetRootHeraldVerdict(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return context.Items.TryGetValue(VerdictItemKey, out var v) && v is RootHeraldVerdict verdict
            ? verdict
            : null;
    }

    /// <summary>
    /// Adds an authorization policy that requires a Root Herald-attested
    /// device passed (verdict = "pass"). Reject warn/fail tokens.
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services.AddAuthorization(opts =>
    /// {
    ///     opts.AddPolicy("RootHeraldAttested", p =&gt; p.RequireRootHerald());
    /// });
    /// </code>
    /// </example>
    public static AuthorizationPolicyBuilder RequireRootHerald(
        this AuthorizationPolicyBuilder builder, string requiredVerdict = "pass")
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.RequireAuthenticatedUser();
        builder.RequireAssertion(ctx =>
        {
            if (ctx.Resource is not HttpContext http) return false;
            var verdict = http.GetRootHeraldVerdict();
            return verdict?.Device.Verdict == requiredVerdict;
        });
        return builder;
    }

    private static RootHeraldVerdict? BuildVerdict(ClaimsPrincipal principal, string issuer)
    {
        var sub = principal.FindFirst("sub")?.Value;
        var aud = principal.FindFirst("aud")?.Value;
        var acr = principal.FindFirst("acr")?.Value;
        var deviceClaim = principal.FindFirst(DeviceClaimType)?.Value;
        if (sub is null || aud is null || acr is null) return null;

        var device = RootHeraldDeviceVerdict.FromClaim(deviceClaim);
        if (device is null) return null;

        var amr = principal.FindAll("amr").Select(c => c.Value).ToArray();
        var authTimeUnix = long.TryParse(principal.FindFirst("auth_time")?.Value, out var at) ? at : 0;
        var expUnix = long.TryParse(principal.FindFirst("exp")?.Value, out var ex) ? ex : 0;

        return new RootHeraldVerdict
        {
            Issuer = issuer,
            UserId = sub,
            Audience = aud,
            Acr = acr,
            Amr = amr,
            AuthTime = DateTimeOffset.FromUnixTimeSeconds(authTimeUnix),
            ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(expUnix),
            Device = device,
        };
    }
}
