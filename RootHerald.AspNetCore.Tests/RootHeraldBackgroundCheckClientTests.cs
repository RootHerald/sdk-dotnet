using System.Net;
using System.Text.Json.Nodes;
using Xunit;

namespace RootHerald.AspNetCore.Tests;

public class RootHeraldBackgroundCheckClientTests
{
    private const string SecretKey = "rh_sk_test_abc123";

    private static (RootHeraldBackgroundCheckClient client, MockHttpMessageHandler handler) Make()
    {
        var handler = new MockHttpMessageHandler();
        var http = new HttpClient(handler);
        var client = new RootHeraldBackgroundCheckClient(SecretKey, "https://api.test.local", http);
        return (client, handler);
    }

    // ── Construction / key hygiene ─────────────────────────────────────────

    [Fact]
    public void Constructor_rejects_empty_secret_key()
    {
        Assert.Throws<ArgumentException>(() => new RootHeraldBackgroundCheckClient(""));
    }

    [Fact]
    public void Constructor_rejects_invalid_prefix_key()
    {
        var ex = Assert.Throws<ArgumentException>(
            () => new RootHeraldBackgroundCheckClient("rh_bogus_nope"));
        Assert.Contains("rh_sk_", ex.Message);
    }

    [Fact]
    public void Constructor_accepts_secret_key()
    {
        var (client, _) = Make();
        Assert.NotNull(client);
    }

    // ── IssueChallenge ─────────────────────────────────────────────────────

    [Fact]
    public async Task IssueChallengeAsync_returns_nonce_and_sends_bearer_secret()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK,
            """{"challengeId":"chal_1","nonce":"nonce_abc","expiresAt":"2026-07-01T00:00:00Z"}""");

        var result = await client.IssueChallengeAsync("device-hint");

        Assert.Equal("chal_1", result.ChallengeId);
        Assert.Equal("nonce_abc", result.Nonce);
        Assert.Equal("2026-07-01T00:00:00Z", result.ExpiresAt);
        Assert.Equal("/api/v1/attestations/challenge", handler.LastRequestPath);
        Assert.Equal($"Bearer {SecretKey}", handler.LastAuthorization);
        Assert.Equal("device-hint", handler.LastBody?["deviceHint"]?.GetValue<string>());
    }

    [Fact]
    public async Task IssueChallengeAsync_throws_on_missing_fields()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK, """{"challengeId":"chal_1"}""");

        await Assert.ThrowsAsync<RootHeraldApiException>(() => client.IssueChallengeAsync());
    }

    // ── Verify ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task VerifyAsync_maps_pass_to_allow()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK,
            """{"verdict":{"verdict":"pass","ueid":"dev_1"}}""");

        var result = await client.VerifyAsync(
            JsonNode.Parse("""{"evidence":"opaque"}""")!,
            new AttestOptions { ChallengeId = "chal_1", Policy = "p" });

        Assert.Equal("allow", result.Verdict);
        Assert.True(result.IsAllowed);
        Assert.Equal("/api/v1/attestations/verify", handler.LastRequestPath);
        Assert.Equal("chal_1", handler.LastBody?["challengeId"]?.GetValue<string>());
        Assert.Equal("p", handler.LastBody?["policy"]?.GetValue<string>());
        // Evidence is passed through verbatim.
        Assert.Equal("opaque", handler.LastBody?["evidence"]?["evidence"]?.GetValue<string>());
    }

    [Fact]
    public async Task VerifyAsync_maps_fail_to_deny_without_throwing()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK, """{"verdict":{"verdict":"fail","ueid":"dev_1"}}""");

        var result = await client.VerifyAsync(
            new JsonObject(), new AttestOptions { ChallengeId = "chal_1" });

        Assert.Equal("deny", result.Verdict);
        Assert.False(result.IsAllowed);
    }

    [Fact]
    public async Task VerifyAsync_requires_challenge_id()
    {
        var (client, _) = Make();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.VerifyAsync(new JsonObject(), new AttestOptions { ChallengeId = "" }));
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, typeof(InvalidSecretKeyException))]
    [InlineData(HttpStatusCode.UnprocessableEntity, typeof(UnknownPolicyException))]
    [InlineData(HttpStatusCode.Conflict, typeof(ChallengeException))]
    [InlineData(HttpStatusCode.BadRequest, typeof(InvalidEvidenceException))]
    [InlineData(HttpStatusCode.TooManyRequests, typeof(QuotaExceededException))]
    public async Task VerifyAsync_maps_error_statuses_to_typed_exceptions(
        HttpStatusCode status, Type expected)
    {
        var (client, handler) = Make();
        handler.Enqueue(status, """{"error":"some_code","message":"boom"}""");

        var ex = await Assert.ThrowsAsync(expected, () =>
            client.VerifyAsync(new JsonObject(), new AttestOptions { ChallengeId = "chal_1" }));
        var api = Assert.IsAssignableFrom<RootHeraldApiException>(ex);
        Assert.Equal((int)status, api.StatusCode);
        Assert.Equal("some_code", api.ErrorCode);
    }

    // ── RelayEnroll: 201 fresh enroll ──────────────────────────────────────

    [Fact]
    public async Task RelayEnrollAsync_201_returns_challenge()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.Created,
            """{"deviceId":"dev_42","credentialBlob":"cred","encryptedSecret":"sec"}""");

        var result = await client.RelayEnrollAsync(new EnrollRequestBlob
        {
            EkPublicKey = "ekpub",
            AkPublicArea = "akpub",
            Platform = "windows",
            EkCertPem = "-----BEGIN CERTIFICATE-----",
        });

        Assert.False(result.AlreadyEnrolled);
        Assert.Equal("dev_42", result.DeviceId);
        Assert.NotNull(result.Challenge);
        Assert.Equal("cred", result.Challenge!.CredentialBlob);
        Assert.Equal("sec", result.Challenge.EncryptedSecret);
        Assert.Equal("/api/v1/devices/enroll", handler.LastRequestPath);
        Assert.Equal($"Bearer {SecretKey}", handler.LastAuthorization);
        // Wire-shape: camelCase keys.
        Assert.Equal("ekpub", handler.LastBody?["ekPublicKey"]?.GetValue<string>());
        Assert.Equal("akpub", handler.LastBody?["akPublicArea"]?.GetValue<string>());
        Assert.Equal("windows", handler.LastBody?["platform"]?.GetValue<string>());
        Assert.Equal("-----BEGIN CERTIFICATE-----", handler.LastBody?["ekCertPem"]?.GetValue<string>());
    }

    [Fact]
    public async Task RelayEnrollAsync_omits_optional_null_fields_on_the_wire()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.Created,
            """{"deviceId":"dev_42","credentialBlob":"cred","encryptedSecret":"sec"}""");

        await client.RelayEnrollAsync(new EnrollRequestBlob
        {
            EkPublicKey = "ekpub",
            AkPublicArea = "akpub",
            Platform = "linux",
        });

        var body = Assert.IsType<JsonObject>(handler.LastBody);
        Assert.False(body.ContainsKey("ekCertPem"));
        Assert.False(body.ContainsKey("ekCertificateChain"));
    }

    // ── RelayEnroll: 409 already-enrolled (the asymmetric path) ─────────────

    [Fact]
    public async Task RelayEnrollAsync_409_returns_already_enrolled_without_throwing()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.Conflict, """{"deviceId":"dev_existing"}""");

        var result = await client.RelayEnrollAsync(new EnrollRequestBlob
        {
            EkPublicKey = "ekpub",
            AkPublicArea = "akpub",
            Platform = "windows",
        });

        Assert.True(result.AlreadyEnrolled);
        Assert.Equal("dev_existing", result.DeviceId);
        Assert.Null(result.Challenge);
    }

    [Fact]
    public async Task RelayEnrollAsync_409_without_deviceId_throws()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.Conflict, """{"error":"conflict"}""");

        var ex = await Assert.ThrowsAsync<RootHeraldApiException>(() =>
            client.RelayEnrollAsync(new EnrollRequestBlob
            {
                EkPublicKey = "ekpub",
                AkPublicArea = "akpub",
                Platform = "windows",
            }));
        Assert.Equal(409, ex.StatusCode);
    }

    [Fact]
    public async Task RelayEnrollAsync_validates_required_fields()
    {
        var (client, _) = Make();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.RelayEnrollAsync(new EnrollRequestBlob
            {
                EkPublicKey = "",
                AkPublicArea = "akpub",
                Platform = "windows",
            }));
    }

    [Fact]
    public async Task RelayEnrollAsync_maps_401_to_invalid_secret_key()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.Unauthorized, """{"error":"bad_key"}""");

        await Assert.ThrowsAsync<InvalidSecretKeyException>(() =>
            client.RelayEnrollAsync(new EnrollRequestBlob
            {
                EkPublicKey = "ekpub",
                AkPublicArea = "akpub",
                Platform = "windows",
            }));
    }

    // ── RelayActivate ──────────────────────────────────────────────────────

    [Fact]
    public async Task RelayActivateAsync_returns_terminal_device_record()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK,
            """{"deviceId":"dev_42","status":"enrolled","enrolledAt":"2026-06-30T12:00:00Z"}""");

        var result = await client.RelayActivateAsync(new EnrollActivationResponse
        {
            DeviceId = "dev_42",
            DecryptedSecret = "secret",
        });

        Assert.Equal("dev_42", result.DeviceId);
        Assert.Equal("enrolled", result.Status);
        Assert.Equal("2026-06-30T12:00:00Z", result.EnrolledAt);
        Assert.Equal("/api/v1/devices/activate", handler.LastRequestPath);
        Assert.Equal($"Bearer {SecretKey}", handler.LastAuthorization);
        Assert.Equal("dev_42", handler.LastBody?["deviceId"]?.GetValue<string>());
        Assert.Equal("secret", handler.LastBody?["decryptedSecret"]?.GetValue<string>());
    }

    [Fact]
    public async Task RelayActivateAsync_validates_required_fields()
    {
        var (client, _) = Make();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.RelayActivateAsync(new EnrollActivationResponse
            {
                DeviceId = "dev_42",
                DecryptedSecret = "",
            }));
    }

    [Fact]
    public async Task RelayActivateAsync_throws_on_missing_device_id()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK, """{"status":"enrolled"}""");

        await Assert.ThrowsAsync<RootHeraldApiException>(() =>
            client.RelayActivateAsync(new EnrollActivationResponse
            {
                DeviceId = "dev_42",
                DecryptedSecret = "secret",
            }));
    }

    // ── Deprecated aliases still work ──────────────────────────────────────

    [Fact]
    public async Task Deprecated_aliases_forward_to_new_helpers()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK,
            """{"challengeId":"chal_1","nonce":"n","expiresAt":"2026-07-01T00:00:00Z"}""");
        handler.Enqueue(HttpStatusCode.OK, """{"verdict":{"verdict":"pass"}}""");

#pragma warning disable CS0618 // intentionally exercising the obsolete aliases
        var challenge = await client.CreateChallengeAsync();
        var verdict = await client.AttestAsync(new JsonObject(),
            new AttestOptions { ChallengeId = challenge.ChallengeId });
#pragma warning restore CS0618

        Assert.Equal("chal_1", challenge.ChallengeId);
        Assert.Equal("allow", verdict.Verdict);
    }
}
