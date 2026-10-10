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

        var result = await client.IssueChallengeAsync();

        Assert.Equal("nonce_abc", result.Nonce);
        Assert.Equal("rhc1.nonce_abc.e30", result.Challenge);
        Assert.Equal("2026-07-01T00:00:00Z", result.ExpiresAt);
        Assert.Equal("/api/v1/attest/challenge", handler.LastRequestPath);
        Assert.Equal($"Bearer {SecretKey}", handler.LastAuthorization);
        Assert.Empty(Assert.IsType<JsonObject>(handler.LastBody));
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
    public async Task VerifyAsync_returns_the_pass_token()
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
                  "quoteVerified": true,
                  "tpmKind": "firmware-tpm",
                  "bootChanged": true,
                  "bootChangedStages": [0, 4]
                }
              },
              "assuranceClaimsMet": ["urn:rootherald:assurance:hardware-backed"],
              "enrollmentRequired": false,
              "key": { "keyId": "stale" }
            }
            """);

        var result = await client.VerifyAsync(
            JsonNode.Parse("""{"evidence":"opaque"}""")!,
            new AttestOptions { Nonce = "nonce_abc", RequestedDisclosureClass = "pseudonymous" });

        Assert.Equal(Verdict.Pass, result.Verdict);
        Assert.True(result.IsPass);
        Assert.Equal(new[] { "urn:rootherald:assurance:hardware-backed" }, result.AssuranceClaimsMet);
        Assert.False(result.EnrollmentRequired);
        // Per-device appraisal fields flow through under verdict.device verbatim.
        Assert.Equal("affirming", result.VerdictData["device"]?["earStatus"]?.GetValue<string>());
        Assert.Equal("tpm20", result.VerdictData["device"]?["attestationType"]?.GetValue<string>());
        Assert.Equal("firmware-tpm", result.VerdictData["device"]?["tpmKind"]?.GetValue<string>());
        Assert.Equal(new[] { 0, 4 }, result.VerdictData["device"]?["bootChangedStages"]?.AsArray().Select(n => n!.GetValue<int>()));
        Assert.Null(result.Expected);
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
    public async Task VerifyAsync_returns_the_fail_token_without_throwing()
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

        Assert.Equal(Verdict.Fail, result.Verdict);
        Assert.False(result.IsPass);
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
    [InlineData(HttpStatusCode.Unauthorized, "invalid_secret_key", typeof(InvalidSecretKeyException))]
    [InlineData(HttpStatusCode.Unauthorized, "activation_refused", typeof(ActivationRefusedException))]
    [InlineData(HttpStatusCode.UnprocessableEntity, "unknown_policy", typeof(UnknownPolicyException))]
    [InlineData(HttpStatusCode.UnprocessableEntity, "admission_refused", typeof(AdmissionRefusedException))]
    [InlineData(HttpStatusCode.UnprocessableEntity, "posture_not_bound", typeof(RootHeraldApiException))]
    [InlineData(HttpStatusCode.PaymentRequired, "plan_lapsed", typeof(RootHeraldApiException))]
    [InlineData(HttpStatusCode.Conflict, "some_code", typeof(ChallengeException))]
    [InlineData(HttpStatusCode.Conflict, "key_rotation_conflict", typeof(RootHeraldApiException))]
    [InlineData(HttpStatusCode.BadRequest, "some_code", typeof(InvalidEvidenceException))]
    [InlineData(HttpStatusCode.BadRequest, "invalid_ask", typeof(InvalidAskException))]
    [InlineData(HttpStatusCode.TooManyRequests, "budget_exhausted", typeof(QuotaExceededException))]
    [InlineData(HttpStatusCode.TooManyRequests, "rate_limited", typeof(RateLimitedException))]
    public async Task VerifyAsync_maps_error_statuses_and_codes_to_typed_exceptions(
        HttpStatusCode status, string code, Type expected)
    {
        var (client, handler) = Make();
        handler.Enqueue(status, $$"""{"error":"{{code}}","message":"boom"}""");

        var ex = await Assert.ThrowsAsync(expected, () =>
            client.VerifyAsync(new JsonObject(), new AttestOptions { Nonce = "nonce_abc" }));
        var api = Assert.IsAssignableFrom<RootHeraldApiException>(ex);
        Assert.Equal(expected, api.GetType());
        Assert.Equal((int)status, api.StatusCode);
        Assert.Equal(code, api.ErrorCode);
    }

    [Fact]
    public async Task A_budget_429_names_the_budget_that_refused()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.TooManyRequests,
            """{"error":"budget_exhausted","message":"budget exhausted","budget":{"id":"bgt_1","name":"Production"}}""",
            ("X-RootHerald-Quota", "budget-exhausted"));

        var ex = await Assert.ThrowsAsync<QuotaExceededException>(() =>
            client.VerifyAsync(new JsonObject(), new AttestOptions { Nonce = "nonce_abc" }));
        Assert.Equal("budget_exhausted", ex.ErrorCode);
        var budget = Assert.IsType<RefusingBudget>(ex.Budget);
        Assert.Equal("bgt_1", budget.Id);
        Assert.Equal("Production", budget.Name);
    }

    [Fact]
    public async Task A_bare_401_is_an_invalid_secret_key()
    {
        var (client, handler) = Make();
        handler.EnqueueRaw(HttpStatusCode.Unauthorized, "");

        await Assert.ThrowsAsync<InvalidSecretKeyException>(() =>
            client.VerifyAsync(new JsonObject(), new AttestOptions { Nonce = "nonce_abc" }));
    }

    [Fact]
    public async Task A_limiter_429_is_rate_limited_with_retry_after_from_the_header()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.TooManyRequests,
            """{"error":"rate_limited","message":"Too many requests","retryAfterSeconds":60}""",
            ("Retry-After", "17"));

        var ex = await Assert.ThrowsAsync<RateLimitedException>(() =>
            client.VerifyAsync(new JsonObject(), new AttestOptions { Nonce = "nonce_abc" }));
        Assert.Equal(17, ex.RetryAfterSeconds);
        Assert.Equal("rate_limited", ex.ErrorCode);
    }

    [Fact]
    public async Task A_limiter_429_falls_back_to_the_body_retry_hint_then_null()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.TooManyRequests, """{"error":"rate_limited","retryAfterSeconds":60}""");
        handler.EnqueueRaw(HttpStatusCode.TooManyRequests, "");

        var fromBody = await Assert.ThrowsAsync<RateLimitedException>(() =>
            client.VerifyAsync(new JsonObject(), new AttestOptions { Nonce = "nonce_abc" }));
        Assert.Equal(60, fromBody.RetryAfterSeconds);

        var bare = await Assert.ThrowsAsync<RateLimitedException>(() =>
            client.VerifyAsync(new JsonObject(), new AttestOptions { Nonce = "nonce_abc" }));
        Assert.Null(bare.RetryAfterSeconds);
    }

    [Fact]
    public async Task A_429_with_the_quota_header_is_the_quota_whatever_the_body()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.TooManyRequests, "{}", ("X-RootHerald-Quota", "budget-exhausted"));

        var ex = await Assert.ThrowsAsync<QuotaExceededException>(() =>
            client.VerifyAsync(new JsonObject(), new AttestOptions { Nonce = "nonce_abc" }));
        Assert.Null(ex.Budget);
    }

    [Theory]
    [InlineData("\"allow\"")]
    [InlineData("\"review\"")]
    [InlineData("\"\"")]
    [InlineData("null")]
    [InlineData("7")]
    public async Task VerifyAsync_refuses_a_verdict_token_outside_pass_warn_fail(string token)
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK, """{"verdict":{"device":{"verdict":""" + token + "}}}");

        var ex = await Assert.ThrowsAsync<RootHeraldApiException>(() =>
            client.VerifyAsync(new JsonObject(), new AttestOptions { Nonce = "nonce_abc" }));
        Assert.Contains("verdict.device.verdict", ex.Message);
    }

    [Fact]
    public void The_owned_HttpClient_times_out_after_30_seconds()
    {
        Assert.Equal(TimeSpan.FromSeconds(30), RootHeraldClient.DefaultTimeout);
    }

    // ── RelayEnroll ────────────────────────────────────────────────────────

    private static EnrollRequestBlob TpmBlob(string platform = "windows") => new()
    {
        Platform = platform,
        EkPublicKey = "ekpub",
        AttestationKey = new AttestationKeyPublic
        {
            PublicArea = "akpub",
            ParentPublicArea = "srk",
            QualifiedName = "qn",
        },
    };

    private static EnrollRequestBlob MacBlob() => new()
    {
        Platform = "macos",
        EkPublicKey = "enclave",
        AkPublicArea = "enclave",
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
        // Wire-shape: camelCase keys, the AK nested, relayed verbatim.
        var body = Assert.IsType<JsonObject>(handler.LastBody);
        Assert.Equal("ekpub", body["ekPublicKey"]?.GetValue<string>());
        Assert.Equal("akpub", body["attestationKey"]?["publicArea"]?.GetValue<string>());
        Assert.Equal("srk", body["attestationKey"]?["parentPublicArea"]?.GetValue<string>());
        Assert.Equal("qn", body["attestationKey"]?["qualifiedName"]?.GetValue<string>());
        Assert.Equal("windows", body["platform"]?.GetValue<string>());
        Assert.Equal("-----BEGIN CERTIFICATE-----", body["ekCertPem"]?.GetValue<string>());
        Assert.Equal("INTC", body["tpmSelfReport"]?["manufacturer"]?.GetValue<string>());
        Assert.Equal("Intel", body["tpmSelfReport"]?["vendorString"]?.GetValue<string>());
        foreach (var k in new[] { "akPublicArea", "challengeId", "deviceId", "nonce", "iosKeyId", "iosAttestationObject" })
            Assert.False(body.ContainsKey(k), $"{k} was sent on a TPM enroll");
    }

    [Fact]
    public async Task RelayEnrollAsync_201_returns_the_macos_challenge()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.Created, """{"enrollmentId":"enr_1","challengeNonce":"bm9uY2U="}""");

        var result = await client.RelayEnrollAsync(MacBlob());

        var challenge = Assert.IsType<EnrollActivationChallenge>(result.Challenge);
        Assert.Equal("enr_1", challenge.EnrollmentId);
        Assert.Equal("bm9uY2U=", challenge.ChallengeNonce);
        Assert.Null(challenge.CredentialBlob);
        Assert.Null(challenge.EncryptedSecret);
        // The macOS body stays flat.
        var body = Assert.IsType<JsonObject>(handler.LastBody);
        Assert.Equal("enclave", body["akPublicArea"]?.GetValue<string>());
        Assert.False(body.ContainsKey("attestationKey"));
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
        Assert.False(body.ContainsKey("attestationKey"));
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
    public async Task RelayEnrollAsync_tpm_platforms_require_the_nested_attestation_key(string platform)
    {
        var (client, handler) = Make();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.RelayEnrollAsync(TpmBlob(platform) with { EkPublicKey = "" }));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.RelayEnrollAsync(TpmBlob(platform) with { AttestationKey = null }));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.RelayEnrollAsync(TpmBlob(platform) with
            {
                AttestationKey = new AttestationKeyPublic { PublicArea = "akpub", ParentPublicArea = "srk", QualifiedName = "" },
            }));
        // The flat 7.0 body is refused before any request.
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.RelayEnrollAsync(TpmBlob(platform) with { AttestationKey = null, AkPublicArea = "akpub" }));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.RelayEnrollAsync(TpmBlob(platform) with { AkPublicArea = "akpub" }));
        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task RelayEnrollAsync_macos_requires_the_flat_body()
    {
        var (client, handler) = Make();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.RelayEnrollAsync(MacBlob() with { EkPublicKey = "" }));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.RelayEnrollAsync(MacBlob() with { AkPublicArea = null }));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.RelayEnrollAsync(MacBlob() with
            {
                AttestationKey = new AttestationKeyPublic { PublicArea = "a", ParentPublicArea = "b", QualifiedName = "c" },
            }));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.RelayEnrollAsync(MacBlob() with { Platform = "freebsd" }));
        Assert.Equal(0, handler.RequestCount);
    }

    private const string DeviceBody =
        """
        {
          "ekPublicKey": "ekpub",
          "attestationKey": { "publicArea": "akpub", "parentPublicArea": "srk", "qualifiedName": "qn", "futureNested": 1 },
          "platform": "linux",
          "ekCertificateChain": ["-----BEGIN CERTIFICATE-----"],
          "tpmSelfReport": { "manufacturer": "INTC", "vendorString": "Intel" },
          "futureField": { "x": [1, 2] }
        }
        """;

    [Fact]
    public async Task RelayEnrollAsync_relays_a_deserialized_device_body_whole()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.Created,
            """{"enrollmentId":"enr_1","credentialBlob":"cred","encryptedSecret":"sec"}""");
        var blob = System.Text.Json.JsonSerializer.Deserialize<EnrollRequestBlob>(DeviceBody)!;

        await client.RelayEnrollAsync(blob);

        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(DeviceBody), handler.LastBody),
            $"body was not relayed whole: {handler.LastBody}");
    }

    [Fact]
    public async Task RelayEnrollAsync_relays_a_json_device_body_verbatim()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.Created,
            """{"enrollmentId":"enr_1","credentialBlob":"cred","encryptedSecret":"sec"}""");

        var result = await client.RelayEnrollAsync(JsonNode.Parse(DeviceBody)!.AsObject());

        Assert.Equal("enr_1", result.Challenge?.EnrollmentId);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(DeviceBody), handler.LastBody));
    }

    [Theory]
    [InlineData("""{"platform":"windows","ekPublicKey":"ekpub","akPublicArea":"akpub"}""")]
    [InlineData("""{"platform":"linux","ekPublicKey":"ekpub","attestationKey":{"publicArea":"a","parentPublicArea":"b"}}""")]
    [InlineData("""{"platform":"macos","ekPublicKey":"e","akPublicArea":"e","attestationKey":{"publicArea":"a","parentPublicArea":"b","qualifiedName":"c"}}""")]
    [InlineData("""{"platform":"ios","iosKeyId":"k","iosAttestationObject":"o"}""")]
    [InlineData("""{"ekPublicKey":"ekpub","attestationKey":{"publicArea":"a","parentPublicArea":"b","qualifiedName":"c"}}""")]
    [InlineData("""{"platform":7}""")]
    public async Task RelayEnrollAsync_refuses_a_malformed_json_body_locally(string body)
    {
        var (client, handler) = Make();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.RelayEnrollAsync(JsonNode.Parse(body)!.AsObject()));
        Assert.Equal(0, handler.RequestCount);
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
