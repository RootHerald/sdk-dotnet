using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Xunit;

namespace RootHerald.AspNetCore.Tests;

/// <summary>
/// The challenge carries the ask and the binding; the key ceremony mints keys;
/// signatures from EC and RSA keys verify locally; the 4xx codes are told apart.
/// </summary>
public class AskModelTests
{
    private const string SecretKey = "rh_sk_test_abc123";

    private static (RootHeraldClient client, MockHttpMessageHandler handler) Make()
    {
        var handler = new MockHttpMessageHandler();
        var http = new HttpClient(handler);
        var client = new RootHeraldClient(SecretKey, "https://api.test.local", http);
        return (client, handler);
    }

    private const string ChallengeBody =
        """{"nonce":"bm9uY2U","challenge":"rhc1.bm9uY2U.eyJhc2siOlsiaWRlbnRpdHkiXX0","expiresAt":"2030-01-01T00:00:00Z"}""";

    private const string KeyChallengeBody =
        """{"nonce":"a2V5bm9uY2U","keyChallenge":"rhk1c.a2V5bm9uY2U.eyJwdXJwb3NlIjoic2lnbiJ9","expiresAt":"2030-01-01T00:00:00Z"}""";

    private static JsonNode TpmCertification() =>
        JsonNode.Parse("""{"publicArea":"p","attest":"a","signature":"s"}""")!;

    // ── IssueChallenge ─────────────────────────────────────────────────────

    [Fact]
    public async Task IssueChallengeAsync_sends_the_ask_and_the_binding_and_returns_the_relay_string()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK, ChallengeBody);

        var result = await client.IssueChallengeAsync(new ChallengeOptions
        {
            Ask = new[] { Ask.Identity },
            ExpectedKey = "key_1",
            ExpectedDevices = new[] { "dev_1", "dev_2" },
        });

        Assert.Equal("rhc1.bm9uY2U.eyJhc2siOlsiaWRlbnRpdHkiXX0", result.Challenge);
        Assert.Equal("bm9uY2U", result.Nonce);
        Assert.Equal("2030-01-01T00:00:00Z", result.ExpiresAt);
        Assert.Equal("/api/v1/attest/challenge", handler.LastRequestPath);
        var body = Assert.IsType<JsonObject>(handler.LastBody);
        var ask = Assert.IsType<JsonArray>(body["ask"]);
        Assert.Equal(new[] { "identity" }, ask.Select(a => a!.GetValue<string>()));
        Assert.Equal("key_1", body["expectedKey"]?.GetValue<string>());
        Assert.Equal(new[] { "dev_1", "dev_2" }, body["expectedDevices"]!.AsArray().Select(a => a!.GetValue<string>()));
        foreach (var k in new[] { "policy", "keyPurpose", "deviceHint" })
            Assert.False(body.ContainsKey(k), $"{k} was sent");
    }

    [Fact]
    public async Task IssueChallengeAsync_default_sends_an_empty_body()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK, ChallengeBody);
        handler.Enqueue(HttpStatusCode.OK, ChallengeBody);

        await client.IssueChallengeAsync();
        var body = Assert.IsType<JsonObject>(handler.LastBody);
        Assert.Empty(body);

        await client.IssueChallengeAsync(new ChallengeOptions { Ask = Array.Empty<string>() });
        body = Assert.IsType<JsonObject>(handler.LastBody);
        Assert.False(body.ContainsKey("ask"));
    }

    [Fact]
    public async Task IssueChallengeAsync_refuses_an_empty_binding_locally()
    {
        var (client, handler) = Make();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.IssueChallengeAsync(new ChallengeOptions { ExpectedKey = "" }));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.IssueChallengeAsync(new ChallengeOptions { ExpectedDevices = Array.Empty<string>() }));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.IssueChallengeAsync(new ChallengeOptions { ExpectedDevices = new[] { "dev_1", "" } }));
        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task IssueChallengeAsync_requires_the_relay_string()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK,
            """{"nonce":"bm9uY2U","expiresAt":"2030-01-01T00:00:00Z"}""");

        await Assert.ThrowsAsync<RootHeraldApiException>(() => client.IssueChallengeAsync());
    }

    [Fact]
    public async Task A_400_invalid_ask_is_a_programming_error_not_invalid_evidence()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.BadRequest, """{"error":"invalid_ask","message":"ask 'key' is not known"}""");

        var ex = await Assert.ThrowsAsync<InvalidAskException>(() =>
            client.IssueChallengeAsync(new ChallengeOptions { Ask = new[] { "key" } }));
        Assert.Equal(400, ex.StatusCode);
        Assert.Equal("invalid_ask", ex.ErrorCode);
    }

    // ── Verify: the echoed binding ─────────────────────────────────────────

    private static string PassFor(string ueid, string? expectedJson)
    {
        var expected = expectedJson is null ? "" : ", \"expected\": " + expectedJson;
        return $$"""
        {
          "verdict": { "device": { "ueid": "{{ueid}}", "verdict": "pass" }{{expected}} },
          "assuranceClaimsMet": [],
          "enrollmentRequired": false
        }
        """;
    }

    [Fact]
    public async Task VerifyAsync_accepts_a_verdict_that_echoes_the_binding()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK, PassFor("dev_1", """{"key":"key_1","devices":["dev_2","dev_1"]}"""));

        var result = await client.VerifyAsync(new JsonObject(), new AttestOptions
        {
            Nonce = "bm9uY2U",
            ExpectedKey = "key_1",
            ExpectedDevices = new[] { "dev_1", "dev_2" },
        });

        Assert.True(result.IsPass);
        var expected = Assert.IsType<ExpectedBinding>(result.Expected);
        Assert.Equal("key_1", expected.Key);
        Assert.Equal(new[] { "dev_2", "dev_1" }, expected.Devices);
        // The binding is enforced server-side; nothing about it is sent on verify.
        var body = Assert.IsType<JsonObject>(handler.LastBody);
        Assert.False(body.ContainsKey("expectedKey"));
        Assert.False(body.ContainsKey("expectedDevices"));
    }

    [Fact]
    public async Task VerifyAsync_refuses_a_verdict_that_does_not_echo_the_expected_key()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK, PassFor("dev_1", null));
        handler.Enqueue(HttpStatusCode.OK, PassFor("dev_1", """{"key":"key_other"}"""));

        await Assert.ThrowsAsync<ExpectedNotEnforcedException>(() =>
            client.VerifyAsync(new JsonObject(), new AttestOptions { Nonce = "bm9uY2U", ExpectedKey = "key_1" }));
        await Assert.ThrowsAsync<ExpectedNotEnforcedException>(() =>
            client.VerifyAsync(new JsonObject(), new AttestOptions { Nonce = "bm9uY2U", ExpectedKey = "key_1" }));
    }

    [Fact]
    public async Task VerifyAsync_refuses_a_verdict_that_does_not_echo_the_expected_devices()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK, PassFor("dev_1", null));
        handler.Enqueue(HttpStatusCode.OK, PassFor("dev_1", """{"devices":["dev_1","dev_3"]}"""));
        // Echoed, but the passing device is outside the list.
        handler.Enqueue(HttpStatusCode.OK, PassFor("dev_9", """{"devices":["dev_1"]}"""));

        var options = new AttestOptions { Nonce = "bm9uY2U", ExpectedDevices = new[] { "dev_1" } };
        await Assert.ThrowsAsync<ExpectedNotEnforcedException>(() => client.VerifyAsync(new JsonObject(), options));
        await Assert.ThrowsAsync<ExpectedNotEnforcedException>(() => client.VerifyAsync(new JsonObject(), options));
        await Assert.ThrowsAsync<ExpectedNotEnforcedException>(() => client.VerifyAsync(new JsonObject(), options));
    }

    [Fact]
    public async Task VerifyAsync_passes_a_failing_verdict_for_another_device_through()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK,
            """{"verdict":{"device":{"ueid":"dev_9","verdict":"fail"},"expected":{"devices":["dev_1"]}}}""");

        var result = await client.VerifyAsync(new JsonObject(),
            new AttestOptions { Nonce = "bm9uY2U", ExpectedDevices = new[] { "dev_1" } });

        Assert.Equal(Verdict.Fail, result.Verdict);
        Assert.Equal("dev_9", result.DeviceId);
    }

    [Fact]
    public async Task VerifyAsync_without_a_binding_ignores_the_echo()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK, PassFor("dev_1", null));

        var result = await client.VerifyAsync(new JsonObject(), new AttestOptions { Nonce = "bm9uY2U" });

        Assert.True(result.IsPass);
        Assert.Null(result.Expected);
    }

    // ── Key ceremony ───────────────────────────────────────────────────────

    [Fact]
    public async Task IssueKeyChallengeAsync_sends_the_purpose_and_returns_the_relay_string()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK, KeyChallengeBody);

        var result = await client.IssueKeyChallengeAsync(new KeyChallengeOptions
        {
            Purpose = KeyPurpose.Sign,
            ExpectedDevices = new[] { "dev_1" },
        });

        Assert.Equal("a2V5bm9uY2U", result.Nonce);
        Assert.Equal("rhk1c.a2V5bm9uY2U.eyJwdXJwb3NlIjoic2lnbiJ9", result.KeyChallenge);
        Assert.Equal("2030-01-01T00:00:00Z", result.ExpiresAt);
        Assert.Equal("/api/v1/keys/challenge", handler.LastRequestPath);
        Assert.Equal($"Bearer {SecretKey}", handler.LastAuthorization);
        var body = Assert.IsType<JsonObject>(handler.LastBody);
        Assert.Equal("sign", body["purpose"]?.GetValue<string>());
        Assert.Equal(new[] { "dev_1" }, body["expectedDevices"]!.AsArray().Select(a => a!.GetValue<string>()));
    }

    [Fact]
    public async Task IssueKeyChallengeAsync_refuses_an_unknown_purpose_locally()
    {
        var (client, handler) = Make();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.IssueKeyChallengeAsync(new KeyChallengeOptions { Purpose = "wrap" }));
        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task IssueKeyChallengeAsync_requires_the_relay_string()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK, """{"nonce":"a2V5bm9uY2U","expiresAt":"2030-01-01T00:00:00Z"}""");

        await Assert.ThrowsAsync<RootHeraldApiException>(() =>
            client.IssueKeyChallengeAsync(new KeyChallengeOptions { Purpose = KeyPurpose.Sign }));
    }

    private const string EcCertified =
        """
        {
          "deviceId": "dev_1",
          "keyId": "key_1",
          "purpose": "sign",
          "alg": "ES256",
          "jwk": { "kty": "EC", "crv": "P-256", "x": "eA", "y": "eQ", "use": "sig" },
          "hardwareBound": true,
          "certifiedAt": "2026-09-07T10:00:00.1234567+00:00"
        }
        """;

    [Fact]
    public async Task CertifyKeyAsync_relays_a_tpm_certification_verbatim_and_parses_the_key()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK, EcCertified);
        var certification = JsonNode.Parse("""{"publicArea":"cHVi","attest":"YXR0","signature":"c2ln","futureField":{"x":1}}""")!;

        var key = await client.CertifyKeyAsync("a2V5bm9uY2U", certification);

        Assert.Equal("/api/v1/keys/certify", handler.LastRequestPath);
        var body = Assert.IsType<JsonObject>(handler.LastBody);
        Assert.Equal("a2V5bm9uY2U", body["nonce"]?.GetValue<string>());
        Assert.True(JsonNode.DeepEquals(certification, body["certification"]));

        Assert.Equal("dev_1", key.DeviceId);
        Assert.Equal("key_1", key.KeyId);
        Assert.Equal(KeyPurpose.Sign, key.Purpose);
        Assert.Equal("ES256", key.Alg);
        Assert.Null(key.Format);
        Assert.True(key.HardwareBound);
        Assert.Equal("EC", key.Jwk["kty"]?.GetValue<string>());
        Assert.Equal("P-256", key.Jwk["crv"]?.GetValue<string>());
        Assert.Equal("eA", key.Jwk["x"]?.GetValue<string>());
        Assert.Equal("eQ", key.Jwk["y"]?.GetValue<string>());
        Assert.Equal(new DateTimeOffset(2026, 9, 7, 10, 0, 0, TimeSpan.Zero).AddTicks(1234567), key.CertifiedAt);
    }

    [Theory]
    [InlineData("""{"platform":"macos","publicKey":"cHVi","signature":"c2ln"}""")]
    [InlineData("""{"platform":"ios","keyId":"a2lk","assertion":"YXNz"}""")]
    public async Task CertifyKeyAsync_relays_an_apple_certification(string certificationJson)
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK,
            """
            {
              "deviceId": "dev_1", "keyId": "key_1", "purpose": "sign", "alg": "ES256",
              "jwk": { "kty": "EC", "crv": "P-256", "x": "eA", "y": "eQ" },
              "hardwareBound": false, "certifiedAt": "2026-09-07T10:00:00Z"
            }
            """);
        var certification = JsonNode.Parse(certificationJson)!;

        var key = await client.CertifyKeyAsync("a2V5bm9uY2U", certification);

        Assert.True(JsonNode.DeepEquals(certification, handler.LastBody!["certification"]));
        Assert.False(key.HardwareBound);
    }

    [Fact]
    public async Task CertifyKeyAsync_parses_an_rsa_key()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK,
            """
            {
              "deviceId": "dev_1", "keyId": "key_2", "purpose": "sign", "alg": "RS256",
              "jwk": { "kty": "RSA", "n": "bW9k", "e": "AQAB" },
              "hardwareBound": true, "certifiedAt": "2026-09-07T10:00:00Z"
            }
            """);

        var key = await client.CertifyKeyAsync("a2V5bm9uY2U", TpmCertification());

        Assert.Equal("RS256", key.Alg);
        Assert.Equal("RSA", key.Jwk["kty"]?.GetValue<string>());
        Assert.Equal("bW9k", key.Jwk["n"]?.GetValue<string>());
        Assert.Equal("AQAB", key.Jwk["e"]?.GetValue<string>());
        Assert.False(key.Jwk.ContainsKey("crv"));
    }

    [Fact]
    public async Task CertifyKeyAsync_parses_a_decrypt_key_with_its_format()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK,
            """
            {
              "deviceId": "dev_1", "keyId": "key_3", "purpose": "decrypt", "alg": "ECDH-ES", "format": "jwe",
              "jwk": { "kty": "EC", "crv": "P-256", "x": "eA", "y": "eQ" },
              "hardwareBound": true, "certifiedAt": "2026-09-07T10:00:00Z"
            }
            """);

        var key = await client.CertifyKeyAsync("a2V5bm9uY2U", TpmCertification());

        Assert.Equal(KeyPurpose.Decrypt, key.Purpose);
        Assert.Equal("ECDH-ES", key.Alg);
        Assert.Equal("jwe", key.Format);
    }

    [Theory]
    [InlineData("""{"keyId":"key_1","purpose":"sign","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"eA","y":"eQ"},"hardwareBound":true,"certifiedAt":"2026-09-07T10:00:00Z"}""")]
    [InlineData("""{"deviceId":"dev_1","purpose":"sign","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"eA","y":"eQ"},"hardwareBound":true,"certifiedAt":"2026-09-07T10:00:00Z"}""")]
    [InlineData("""{"deviceId":"dev_1","keyId":"key_1","purpose":"wrap","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"eA","y":"eQ"},"hardwareBound":true,"certifiedAt":"2026-09-07T10:00:00Z"}""")]
    [InlineData("""{"deviceId":"dev_1","keyId":"key_1","purpose":"sign","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"eA","y":"eQ"},"certifiedAt":"2026-09-07T10:00:00Z"}""")]
    [InlineData("""{"deviceId":"dev_1","keyId":"key_1","purpose":"sign","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"eA","y":"eQ"},"hardwareBound":true,"certifiedAt":"yesterday"}""")]
    [InlineData("""{"deviceId":"dev_1","keyId":"key_1","purpose":"sign","alg":"ES256","jwk":{"kty":"EC","crv":"P-384","x":"eA","y":"eQ"},"hardwareBound":true,"certifiedAt":"2026-09-07T10:00:00Z"}""")]
    [InlineData("""{"deviceId":"dev_1","keyId":"key_1","purpose":"sign","alg":"RS256","jwk":{"kty":"EC","crv":"P-256","x":"eA","y":"eQ"},"hardwareBound":true,"certifiedAt":"2026-09-07T10:00:00Z"}""")]
    [InlineData("""{"deviceId":"dev_1","keyId":"key_1","purpose":"sign","alg":"ES256","jwk":{"kty":"RSA","n":"bW9k","e":"AQAB"},"hardwareBound":true,"certifiedAt":"2026-09-07T10:00:00Z"}""")]
    [InlineData("""{"deviceId":"dev_1","keyId":"key_1","purpose":"sign","alg":"ES256","jwk":{"kty":"RSA","n":"bW9k"},"hardwareBound":true,"certifiedAt":"2026-09-07T10:00:00Z"}""")]
    [InlineData("""{"deviceId":"dev_1","keyId":"key_1","purpose":"decrypt","alg":"ECDH-ES","format":"pgp","jwk":{"kty":"EC","crv":"P-256","x":"eA","y":"eQ"},"hardwareBound":true,"certifiedAt":"2026-09-07T10:00:00Z"}""")]
    [InlineData("[]")]
    public async Task CertifyKeyAsync_refuses_a_malformed_key(string body)
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK, body);

        var ex = await Assert.ThrowsAsync<RootHeraldApiException>(() =>
            client.CertifyKeyAsync("a2V5bm9uY2U", TpmCertification()));
        Assert.Equal(200, ex.StatusCode);
    }

    [Theory]
    [InlineData("""{"publicArea":"p","attest":"a"}""")]
    [InlineData("""{"publicArea":"p","attest":"a","signature":""}""")]
    [InlineData("""{"publicKey":"p","signature":"s"}""")]
    [InlineData("""{}""")]
    [InlineData("""["p","a","s"]""")]
    public async Task CertifyKeyAsync_refuses_a_malformed_certification_locally(string certificationJson)
    {
        var (client, handler) = Make();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.CertifyKeyAsync("a2V5bm9uY2U", JsonNode.Parse(certificationJson)!));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.CertifyKeyAsync("", TpmCertification()));
        Assert.Equal(0, handler.RequestCount);
    }

    [Theory]
    [InlineData(HttpStatusCode.Conflict, "key_rotation_conflict", typeof(RootHeraldApiException))]
    [InlineData(HttpStatusCode.Conflict, "challenge_consumed", typeof(ChallengeException))]
    [InlineData(HttpStatusCode.UnprocessableEntity, "expected_unknown", typeof(RootHeraldApiException))]
    [InlineData(HttpStatusCode.UnprocessableEntity, "key_disclosure_too_low", typeof(RootHeraldApiException))]
    public async Task CertifyKeyAsync_maps_the_key_ceremony_refusals(HttpStatusCode status, string code, Type expected)
    {
        var (client, handler) = Make();
        handler.Enqueue(status, $$"""{"error":"{{code}}","message":"detail"}""");

        var ex = await Assert.ThrowsAsync(expected, () =>
            client.CertifyKeyAsync("a2V5bm9uY2U", TpmCertification()));
        var api = Assert.IsAssignableFrom<RootHeraldApiException>(ex);
        Assert.Equal(expected, api.GetType());
        Assert.Equal((int)status, api.StatusCode);
        Assert.Equal(code, api.ErrorCode);
    }

    // ── 422 by error code ──────────────────────────────────────────────────

    [Theory]
    [InlineData("admission_refused", typeof(AdmissionRefusedException))]
    [InlineData("unknown_policy", typeof(UnknownPolicyException))]
    [InlineData(null, typeof(UnknownPolicyException))]
    [InlineData("posture_not_bound", typeof(RootHeraldApiException))]
    [InlineData("expected_unknown", typeof(RootHeraldApiException))]
    public async Task A_422_is_told_apart_by_its_error_code(string? code, Type expected)
    {
        var (client, handler) = Make();
        var body = code is null
            ? """{"message":"detail"}"""
            : $$"""{"error":"{{code}}","message":"detail: {{code}}"}""";
        handler.Enqueue(HttpStatusCode.UnprocessableEntity, body);

        var ex = await Assert.ThrowsAsync(expected, () =>
            client.VerifyAsync(new JsonObject(), new AttestOptions { Nonce = "bm9uY2U" }));
        var api = Assert.IsAssignableFrom<RootHeraldApiException>(ex);
        Assert.Equal(422, api.StatusCode);
        Assert.Equal(code, api.ErrorCode);
        Assert.StartsWith("detail", api.Message);
    }

    // ── RelayEnroll admission ──────────────────────────────────────────────

    private static EnrollRequestBlob Blob() => new()
    {
        EkPublicKey = "ekpub",
        AttestationKey = new AttestationKeyPublic { PublicArea = "akpub", ParentPublicArea = "srk", QualifiedName = "qn" },
        Platform = "windows",
    };

    [Fact]
    public async Task RelayEnrollAsync_surfaces_admission_refused_with_the_class()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.UnprocessableEntity,
            """{"error":"admission_refused","message":"policy requires a discrete TPM; device class is firmware-tpm"}""");

        var ex = await Assert.ThrowsAsync<AdmissionRefusedException>(() => client.RelayEnrollAsync(Blob()));

        Assert.Equal("admission_refused", ex.ErrorCode);
        Assert.Contains("firmware-tpm", ex.Message);
    }

    [Theory]
    [InlineData("wire_version_unsupported")]
    [InlineData("invalid_enroll_shape")]
    public async Task RelayEnrollAsync_maps_a_400_shape_refusal_to_invalid_evidence(string code)
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.BadRequest, $$"""{"error":"{{code}}","message":"detail"}""");

        var ex = await Assert.ThrowsAsync<InvalidEvidenceException>(() => client.RelayEnrollAsync(Blob()));
        Assert.Equal(code, ex.ErrorCode);
    }

    // ── VerifyKeySignature ─────────────────────────────────────────────────

    private static JsonObject JwkFor(ECDsa key)
    {
        var p = key.ExportParameters(false);
        return new JsonObject
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Base64Url(p.Q.X!),
            ["y"] = Base64Url(p.Q.Y!),
        };
    }

    private static JsonObject JwkFor(RSA key)
    {
        var p = key.ExportParameters(false);
        return new JsonObject
        {
            ["kty"] = "RSA",
            ["n"] = Base64Url(p.Modulus!),
            ["e"] = Base64Url(p.Exponent!),
        };
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    [Fact]
    public void VerifyKeySignature_accepts_raw_and_der_es256_signatures()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwk = JwkFor(key);
        var message = Encoding.UTF8.GetBytes("""{"action":"transfer","amount":100}""");

        var raw = key.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var der = key.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        Assert.Equal(64, raw.Length);
        Assert.True(RootHeraldClient.VerifyKeySignature(jwk, message, raw));
        Assert.True(RootHeraldClient.VerifyKeySignature(jwk, message, der));

        // Padded base64url coordinates are tolerated.
        var padded = (JsonObject)jwk.DeepClone();
        padded["x"] = Convert.ToBase64String(key.ExportParameters(false).Q.X!).Replace('+', '-').Replace('/', '_');
        Assert.True(RootHeraldClient.VerifyKeySignature(padded, message, der));
    }

    [Fact]
    public void VerifyKeySignature_accepts_rs256_over_a_2048_bit_modulus()
    {
        using var key = RSA.Create(2048);
        var jwk = JwkFor(key);
        var message = Encoding.UTF8.GetBytes("""{"action":"transfer","amount":100}""");

        var signature = key.SignData(message, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        Assert.Equal(256, signature.Length);
        Assert.True(RootHeraldClient.VerifyKeySignature(jwk, message, signature));
        Assert.False(RootHeraldClient.VerifyKeySignature(jwk, Encoding.UTF8.GetBytes("tampered"), signature));

        var flipped = (byte[])signature.Clone();
        flipped[10] ^= 0x01;
        Assert.False(RootHeraldClient.VerifyKeySignature(jwk, message, flipped));

        // PSS is not RS256.
        var pss = key.SignData(message, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        Assert.False(RootHeraldClient.VerifyKeySignature(jwk, message, pss));
        // SHA-384 is not RS256.
        var sha384 = key.SignData(message, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
        Assert.False(RootHeraldClient.VerifyKeySignature(jwk, message, sha384));

        // The signature must be exactly the modulus length.
        Assert.False(RootHeraldClient.VerifyKeySignature(jwk, message, signature.AsSpan(0, 255)));
        Assert.False(RootHeraldClient.VerifyKeySignature(jwk, message, signature.Concat(new byte[] { 0 }).ToArray()));

        using var other = RSA.Create(2048);
        Assert.False(RootHeraldClient.VerifyKeySignature(JwkFor(other), message, signature));

        // Malformed keys are false, not exceptions.
        var bad = (JsonObject)jwk.DeepClone();
        bad.Remove("e");
        Assert.False(RootHeraldClient.VerifyKeySignature(bad, message, signature));
        bad = (JsonObject)jwk.DeepClone();
        bad["n"] = "!!not base64!!";
        Assert.False(RootHeraldClient.VerifyKeySignature(bad, message, signature));
        bad = (JsonObject)jwk.DeepClone();
        bad["n"] = 42;
        Assert.False(RootHeraldClient.VerifyKeySignature(bad, message, signature));
    }

    [Fact]
    public void VerifyKeySignature_refuses_an_rsa_modulus_under_2048_bits()
    {
        using var key = RSA.Create(1024);
        var jwk = JwkFor(key);
        var message = Encoding.UTF8.GetBytes("short");
        var signature = key.SignData(message, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        Assert.Equal(128, signature.Length);
        Assert.False(RootHeraldClient.VerifyKeySignature(jwk, message, signature));
    }

    [Fact]
    public void VerifyKeySignature_rejects_tampering_and_never_throws()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwk = JwkFor(key);
        var message = Encoding.UTF8.GetBytes("original");
        var raw = key.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var der = key.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        Assert.False(RootHeraldClient.VerifyKeySignature(jwk, Encoding.UTF8.GetBytes("tampered"), raw));
        Assert.False(RootHeraldClient.VerifyKeySignature(jwk, Encoding.UTF8.GetBytes("tampered"), der));

        var flipped = (byte[])raw.Clone();
        flipped[10] ^= 0x01;
        Assert.False(RootHeraldClient.VerifyKeySignature(jwk, message, flipped));

        Assert.False(RootHeraldClient.VerifyKeySignature(JwkFor(other), message, der));

        // Malformed signatures are false, not exceptions.
        Assert.False(RootHeraldClient.VerifyKeySignature(jwk, message, ReadOnlySpan<byte>.Empty));
        Assert.False(RootHeraldClient.VerifyKeySignature(jwk, message, Encoding.ASCII.GetBytes("not a signature at all, definitely not DER")));
        Assert.False(RootHeraldClient.VerifyKeySignature(jwk, message, der.AsSpan(0, der.Length / 2)));
        Assert.False(RootHeraldClient.VerifyKeySignature(jwk, message, new byte[64]));
        Assert.False(RootHeraldClient.VerifyKeySignature(jwk, message, Enumerable.Repeat((byte)0xff, 64).ToArray()));
        Assert.False(RootHeraldClient.VerifyKeySignature(jwk, message, raw.AsSpan(0, 63)));

        // Malformed keys are false, not exceptions.
        var bad = (JsonObject)jwk.DeepClone();
        bad["kty"] = "RSA";
        Assert.False(RootHeraldClient.VerifyKeySignature(bad, message, der));
        bad = (JsonObject)jwk.DeepClone();
        bad["kty"] = "oct";
        Assert.False(RootHeraldClient.VerifyKeySignature(bad, message, der));
        bad = (JsonObject)jwk.DeepClone();
        bad["crv"] = "secp256k1";
        Assert.False(RootHeraldClient.VerifyKeySignature(bad, message, der));
        bad = (JsonObject)jwk.DeepClone();
        bad["crv"] = "P-384";
        Assert.False(RootHeraldClient.VerifyKeySignature(bad, message, der));
        bad = (JsonObject)jwk.DeepClone();
        var y = key.ExportParameters(false).Q.Y!;
        y[^1] ^= 0x01; // off the curve
        bad["y"] = Base64Url(y);
        Assert.False(RootHeraldClient.VerifyKeySignature(bad, message, der));
        bad = (JsonObject)jwk.DeepClone();
        bad["x"] = Base64Url(key.ExportParameters(false).Q.X!.AsSpan(0, 31).ToArray());
        Assert.False(RootHeraldClient.VerifyKeySignature(bad, message, der));
        bad = (JsonObject)jwk.DeepClone();
        bad["x"] = "!!not base64!!";
        Assert.False(RootHeraldClient.VerifyKeySignature(bad, message, der));
        bad = (JsonObject)jwk.DeepClone();
        bad.Remove("y");
        Assert.False(RootHeraldClient.VerifyKeySignature(bad, message, der));
        bad = (JsonObject)jwk.DeepClone();
        bad["x"] = 42;
        Assert.False(RootHeraldClient.VerifyKeySignature(bad, message, der));
        Assert.False(RootHeraldClient.VerifyKeySignature(new JsonObject(), message, der));
        Assert.False(RootHeraldClient.VerifyKeySignature(null!, message, der));
    }

    [Fact]
    public void VerifyKeySignature_does_not_mix_key_families()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var rsa = RSA.Create(2048);
        var message = Encoding.UTF8.GetBytes("message");
        var ecSig = ec.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var rsaSig = rsa.SignData(message, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        Assert.False(RootHeraldClient.VerifyKeySignature(JwkFor(ec), message, rsaSig));
        Assert.False(RootHeraldClient.VerifyKeySignature(JwkFor(rsa), message, ecSig));
    }
}
