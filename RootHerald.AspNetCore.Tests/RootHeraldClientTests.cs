using System.Net;
using System.Text.Json.Nodes;
using Xunit;

namespace RootHerald.AspNetCore.Tests;

public class RootHeraldBackgroundCheckClientTests
{
    private const string SecretKey = "rh_sk_test_abc123";

    private static (RootHeraldClient client, MockHttpMessageHandler handler) Make()
    {
        var handler = new MockHttpMessageHandler();
        var http = new HttpClient(handler);
        var client = new RootHeraldClient(SecretKey, "https://api.test.local", http);
        return (client, handler);
    }

    // ── Construction / key hygiene ─────────────────────────────────────────

    [Fact]
    public void Constructor_rejects_empty_secret_key()
    {
        Assert.Throws<ArgumentException>(() => new RootHeraldClient(""));
    }

    [Fact]
    public void Constructor_rejects_invalid_prefix_key()
    {
        var ex = Assert.Throws<ArgumentException>(
            () => new RootHeraldClient("rh_bogus_nope"));
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
            """{"nonce":"nonce_abc","challenge":"rhc1.nonce_abc.e30","expiresAt":"2026-07-01T00:00:00Z"}""");

        var result = await client.IssueChallengeAsync("device-hint");

        Assert.Equal("nonce_abc", result.Nonce);
        Assert.Equal("rhc1.nonce_abc.e30", result.Challenge);
        Assert.Equal("2026-07-01T00:00:00Z", result.ExpiresAt);
        Assert.Equal("/api/v1/attest/challenge", handler.LastRequestPath);
        Assert.Equal($"Bearer {SecretKey}", handler.LastAuthorization);
        Assert.Equal("device-hint", handler.LastBody?["deviceHint"]?.GetValue<string>());
    }

    [Theory]
    [InlineData("""{"challenge":"rhc1.n.e30","expiresAt":"2026-07-01T00:00:00Z"}""")]
    [InlineData("""{"nonce":"n","expiresAt":"2026-07-01T00:00:00Z"}""")]
    [InlineData("""{"nonce":"n","challenge":"rhc1.n.e30"}""")]
    public async Task IssueChallengeAsync_throws_on_missing_fields(string body)
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK, body);

        await Assert.ThrowsAsync<RootHeraldApiException>(() => client.IssueChallengeAsync());
    }

    // ── Verify ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task VerifyAsync_maps_pass_to_allow()
    {
        var (client, handler) = Make();
        // Real wire shape: the pass/fail token lives at verdict.device.verdict,
        // with assuranceClaimsMet + enrollmentRequired as top-level siblings.
        handler.Enqueue(HttpStatusCode.OK,
            """
            {
              "verdict": {
                "acr": "urn:rootherald:acr:hardware",
                "amr": ["hwk"],
                "device": {
                  "ueid": "dev_1",
                  "disclosureClass": "pseudonymous",
                  "earStatus": "affirming",
                  "verdict": "pass",
                  "attestationType": "tpm20",
                  "quoteVerified": true
                }
              },
              "assuranceClaimsMet": ["urn:rootherald:assurance:hardware-backed"],
              "enrollmentRequired": false
            }
            """);

        var result = await client.VerifyAsync(
            JsonNode.Parse("""{"evidence":"opaque"}""")!,
            new AttestOptions { Nonce = "nonce_abc", RequestedDisclosureClass = "pseudonymous" });

        Assert.Equal("allow", result.Verdict);
        Assert.True(result.IsAllowed);
        Assert.Equal(new[] { "urn:rootherald:assurance:hardware-backed" }, result.AssuranceClaimsMet);
        Assert.False(result.EnrollmentRequired);
        // Per-device appraisal fields flow through under verdict.device verbatim.
        Assert.Equal("affirming", result.VerdictData["device"]?["earStatus"]?.GetValue<string>());
        Assert.Equal("tpm20", result.VerdictData["device"]?["attestationType"]?.GetValue<string>());
        Assert.Equal("/api/v1/attest/verify", handler.LastRequestPath);
        Assert.Equal("nonce_abc", handler.LastBody?["nonce"]?.GetValue<string>());
        Assert.False(handler.LastBody!.AsObject().ContainsKey("challengeId"), "challengeId was sent; the nonce is the handle");
        Assert.Equal("pseudonymous", handler.LastBody?["requestedDisclosureClass"]?.GetValue<string>());
        // Policies bind to the API key; the server refuses the field with 400.
        Assert.False(handler.LastBody!.AsObject().ContainsKey("policy"), "policy was sent; policies bind to the API key");
        // Evidence is passed through verbatim.
        Assert.Equal("opaque", handler.LastBody?["evidence"]?["evidence"]?.GetValue<string>());
    }

    [Fact]
    public async Task VerifyAsync_maps_fail_to_deny_without_throwing()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK,
            """
            {
              "verdict": {
                "acr": "urn:rootherald:acr:hardware",
                "device": { "ueid": "dev_1", "verdict": "fail", "earStatus": "contraindicated" }
              },
              "assuranceClaimsMet": [],
              "enrollmentRequired": true
            }
            """);

        var result = await client.VerifyAsync(
            new JsonObject(), new AttestOptions { Nonce = "nonce_abc" });

        Assert.Equal("deny", result.Verdict);
        Assert.False(result.IsAllowed);
        Assert.True(result.EnrollmentRequired);
        Assert.Empty(result.AssuranceClaimsMet);
    }

    [Fact]
    public async Task VerifyAsync_omits_disclosure_class_when_not_supplied()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK,
            """{"verdict":{"device":{"verdict":"pass"}},"assuranceClaimsMet":[],"enrollmentRequired":false}""");

        await client.VerifyAsync(new JsonObject(), new AttestOptions { Nonce = "nonce_abc" });

        var body = Assert.IsType<JsonObject>(handler.LastBody);
        Assert.False(body.ContainsKey("requestedDisclosureClass"));
    }

    [Fact]
    public async Task VerifyAsync_requires_nonce()
    {
        var (client, _) = Make();
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            client.VerifyAsync(new JsonObject(), new AttestOptions { Nonce = "" }));
        Assert.Contains("Nonce", ex.Message);
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
            client.VerifyAsync(new JsonObject(), new AttestOptions { Nonce = "nonce_abc" }));
        var api = Assert.IsAssignableFrom<RootHeraldApiException>(ex);
        Assert.Equal((int)status, api.StatusCode);
        Assert.Equal("some_code", api.ErrorCode);
    }

    // ── RelayEnroll ────────────────────────────────────────────────────────

    private static EnrollRequestBlob TpmBlob(string platform = "windows") => new()
    {
        Platform = platform,
        EkPublicKey = "ekpub",
        AkPublicArea = "akpub",
    };

    private static EnrollRequestBlob IosBlob() => new()
    {
        Platform = "ios",
        IosKeyId = "keyid",
        IosAttestationObject = "attobj",
        Nonce = "bm9uY2U",
    };

    [Fact]
    public async Task RelayEnrollAsync_201_returns_the_tpm_challenge()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.Created,
            """{"enrollmentId":"enr_1","credentialBlob":"cred","encryptedSecret":"sec"}""");

        var result = await client.RelayEnrollAsync(TpmBlob() with
        {
            EkCertPem = "-----BEGIN CERTIFICATE-----",
            TpmSelfReport = new TpmSelfReport { Manufacturer = "INTC", VendorString = "Intel" },
        });

        var challenge = Assert.IsType<EnrollActivationChallenge>(result.Challenge);
        Assert.Equal("enr_1", challenge.EnrollmentId);
        Assert.Equal("cred", challenge.CredentialBlob);
        Assert.Equal("sec", challenge.EncryptedSecret);
        Assert.Null(challenge.ChallengeNonce);
        Assert.Equal("/api/v1/attest/enroll", handler.LastRequestPath);
        Assert.Equal($"Bearer {SecretKey}", handler.LastAuthorization);
        // Wire-shape: camelCase keys, relayed verbatim.
        var body = Assert.IsType<JsonObject>(handler.LastBody);
        Assert.Equal("ekpub", body["ekPublicKey"]?.GetValue<string>());
        Assert.Equal("akpub", body["akPublicArea"]?.GetValue<string>());
        Assert.Equal("windows", body["platform"]?.GetValue<string>());
        Assert.Equal("-----BEGIN CERTIFICATE-----", body["ekCertPem"]?.GetValue<string>());
        Assert.Equal("INTC", body["tpmSelfReport"]?["manufacturer"]?.GetValue<string>());
        Assert.Equal("Intel", body["tpmSelfReport"]?["vendorString"]?.GetValue<string>());
        foreach (var k in new[] { "challengeId", "deviceId", "nonce", "iosKeyId", "iosAttestationObject" })
            Assert.False(body.ContainsKey(k), $"{k} was sent on a TPM enroll");
    }

    [Fact]
    public async Task RelayEnrollAsync_201_returns_the_macos_challenge()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.Created, """{"enrollmentId":"enr_1","challengeNonce":"bm9uY2U="}""");

        var result = await client.RelayEnrollAsync(TpmBlob("macos"));

        var challenge = Assert.IsType<EnrollActivationChallenge>(result.Challenge);
        Assert.Equal("enr_1", challenge.EnrollmentId);
        Assert.Equal("bm9uY2U=", challenge.ChallengeNonce);
        Assert.Null(challenge.CredentialBlob);
        Assert.Null(challenge.EncryptedSecret);
    }

    [Fact]
    public async Task RelayEnrollAsync_ios_sends_the_app_attest_body_and_accepts_an_empty_201()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.Created, "{}");

        var result = await client.RelayEnrollAsync(IosBlob());

        Assert.Null(result.Challenge);
        Assert.Equal("/api/v1/attest/enroll", handler.LastRequestPath);
        var body = Assert.IsType<JsonObject>(handler.LastBody);
        Assert.Equal("ios", body["platform"]?.GetValue<string>());
        Assert.Equal("keyid", body["iosKeyId"]?.GetValue<string>());
        Assert.Equal("attobj", body["iosAttestationObject"]?.GetValue<string>());
        Assert.Equal("bm9uY2U", body["nonce"]?.GetValue<string>());
        Assert.False(body.ContainsKey("ekPublicKey"));
        Assert.False(body.ContainsKey("akPublicArea"));
    }

    [Fact]
    public async Task RelayEnrollAsync_ios_still_returns_a_challenge_the_server_sends()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.Created, """{"enrollmentId":"enr_1","challengeNonce":"n"}""");

        var result = await client.RelayEnrollAsync(IosBlob());

        Assert.Equal("enr_1", result.Challenge?.EnrollmentId);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("""{"credentialBlob":"cred","encryptedSecret":"sec"}""")]
    [InlineData("""{"enrollmentId":"","credentialBlob":"cred","encryptedSecret":"sec"}""")]
    [InlineData("""{"enrollmentId":"enr_1","credentialBlob":"cred"}""")]
    [InlineData("""{"enrollmentId":"enr_1","encryptedSecret":"sec"}""")]
    [InlineData("""{"enrollmentId":"enr_1"}""")]
    [InlineData("""{"deviceId":"dev_42","credentialBlob":"cred","encryptedSecret":"sec"}""")]
    [InlineData("[]")]
    public async Task RelayEnrollAsync_rejects_an_incomplete_201(string body)
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.Created, body);

        var ex = await Assert.ThrowsAsync<RootHeraldApiException>(() => client.RelayEnrollAsync(TpmBlob()));
        Assert.Equal(201, ex.StatusCode);
    }

    [Fact]
    public async Task RelayEnrollAsync_omits_optional_null_fields_on_the_wire()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.Created,
            """{"enrollmentId":"enr_1","credentialBlob":"cred","encryptedSecret":"sec"}""");

        await client.RelayEnrollAsync(TpmBlob("linux"));

        var body = Assert.IsType<JsonObject>(handler.LastBody);
        Assert.False(body.ContainsKey("ekCertPem"));
        Assert.False(body.ContainsKey("ekCertificateChain"));
        Assert.False(body.ContainsKey("tpmSelfReport"));
    }

    [Theory]
    [InlineData("windows")]
    [InlineData("linux")]
    [InlineData("macos")]
    public async Task RelayEnrollAsync_tpm_platforms_require_the_key_material(string platform)
    {
        var (client, _) = Make();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.RelayEnrollAsync(TpmBlob(platform) with { EkPublicKey = "" }));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.RelayEnrollAsync(TpmBlob(platform) with { AkPublicArea = null }));
    }

    [Fact]
    public async Task RelayEnrollAsync_ios_requires_the_app_attest_fields()
    {
        var (client, _) = Make();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.RelayEnrollAsync(IosBlob() with { IosKeyId = null }));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.RelayEnrollAsync(IosBlob() with { IosAttestationObject = "" }));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.RelayEnrollAsync(IosBlob() with { Nonce = null }));
        // TPM key material does not stand in for the App Attest fields.
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.RelayEnrollAsync(TpmBlob("ios")));
    }

    [Fact]
    public async Task RelayEnrollAsync_maps_401_to_invalid_secret_key()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.Unauthorized, """{"error":"bad_key"}""");

        await Assert.ThrowsAsync<InvalidSecretKeyException>(() => client.RelayEnrollAsync(TpmBlob()));
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
            EnrollmentId = "enr_1",
            DecryptedSecret = "secret",
        });

        Assert.Equal("dev_42", result.DeviceId);
        Assert.Equal("enrolled", result.Status);
        Assert.Equal("2026-06-30T12:00:00Z", result.EnrolledAt);
        Assert.Equal("/api/v1/attest/activate", handler.LastRequestPath);
        Assert.Equal($"Bearer {SecretKey}", handler.LastAuthorization);
        var body = Assert.IsType<JsonObject>(handler.LastBody);
        Assert.Equal("enr_1", body["enrollmentId"]?.GetValue<string>());
        Assert.Equal("secret", body["decryptedSecret"]?.GetValue<string>());
        foreach (var k in new[] { "deviceId", "challengeId", "akPublicKey", "signature" })
            Assert.False(body.ContainsKey(k), $"{k} was sent on activate");
    }

    [Fact]
    public async Task RelayActivateAsync_sends_the_macos_signature()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK, """{"deviceId":"dev_42","status":"enrolled"}""");

        await client.RelayActivateAsync(new EnrollActivationResponse
        {
            EnrollmentId = "enr_1",
            Signature = "sig",
        });

        var body = Assert.IsType<JsonObject>(handler.LastBody);
        Assert.Equal("enr_1", body["enrollmentId"]?.GetValue<string>());
        Assert.Equal("sig", body["signature"]?.GetValue<string>());
        Assert.False(body.ContainsKey("decryptedSecret"));
    }

    [Fact]
    public async Task RelayActivateAsync_validates_required_fields()
    {
        var (client, _) = Make();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.RelayActivateAsync(new EnrollActivationResponse
            {
                EnrollmentId = "",
                DecryptedSecret = "secret",
            }));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.RelayActivateAsync(new EnrollActivationResponse
            {
                EnrollmentId = "enr_1",
            }));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.RelayActivateAsync(new EnrollActivationResponse
            {
                EnrollmentId = "enr_1",
                DecryptedSecret = "",
                Signature = "",
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
                EnrollmentId = "enr_1",
                DecryptedSecret = "secret",
            }));
    }
}
