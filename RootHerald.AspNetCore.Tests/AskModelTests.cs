using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Xunit;

namespace RootHerald.AspNetCore.Tests;

/// <summary>
/// The challenge carries the ask: the ask goes out on the challenge, a passing
/// verdict with a key ask brings the certified key back, enrollment can be
/// admitted against a challenge, and the two new 422 codes are told apart.
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
        """{"challengeId":"chal_1","challenge":"rhc1.bm9uY2U.eyJhc2siOlsiaWRlbnRpdHkiLCJrZXkiXX0","nonce":"bm9uY2U=","expiresAt":"2030-01-01T00:00:00Z"}""";

    // ── IssueChallenge ─────────────────────────────────────────────────────

    [Fact]
    public async Task IssueChallengeAsync_sends_the_ask_and_returns_the_relay_string()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK, ChallengeBody);

        var result = await client.IssueChallengeAsync(new ChallengeOptions
        {
            Ask = new[] { Ask.Identity, Ask.Key },
            KeyPurpose = "sign",
            DeviceHint = "laptop-7",
        });

        Assert.Equal("chal_1", result.ChallengeId);
        Assert.Equal("rhc1.bm9uY2U.eyJhc2siOlsiaWRlbnRpdHkiLCJrZXkiXX0", result.Challenge);
        Assert.Equal("bm9uY2U=", result.Nonce);
        Assert.Equal("/api/v1/attest/challenge", handler.LastRequestPath);
        var body = Assert.IsType<JsonObject>(handler.LastBody);
        var ask = Assert.IsType<JsonArray>(body["ask"]);
        Assert.Equal(new[] { "identity", "key" }, ask.Select(a => a!.GetValue<string>()));
        Assert.Equal("sign", body["keyPurpose"]?.GetValue<string>());
        // Policies bind to the API key; the server refuses the field with 400.
        Assert.False(body.ContainsKey("policy"), "policy was sent; policies bind to the API key");
        Assert.Equal("laptop-7", body["deviceHint"]?.GetValue<string>());
    }

    [Fact]
    public async Task IssueChallengeAsync_default_sends_no_ask()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK, ChallengeBody);
        handler.Enqueue(HttpStatusCode.OK, ChallengeBody);

        await client.IssueChallengeAsync();
        var body = Assert.IsType<JsonObject>(handler.LastBody);
        foreach (var k in new[] { "ask", "policy", "keyPurpose", "deviceHint" })
            Assert.False(body.ContainsKey(k), $"{k} was sent; the default ask is the server's");

        await client.IssueChallengeAsync(new ChallengeOptions { Ask = Array.Empty<string>() });
        body = Assert.IsType<JsonObject>(handler.LastBody);
        Assert.False(body.ContainsKey("ask"));
    }

    [Fact]
    public async Task IssueChallengeAsync_tolerates_a_server_without_challenge()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK,
            """{"challengeId":"chal_1","nonce":"bm9uY2U=","expiresAt":"2030-01-01T00:00:00Z"}""");

        var result = await client.IssueChallengeAsync();

        Assert.Null(result.Challenge);
        Assert.Equal("bm9uY2U=", result.Nonce);
    }

    // ── Verify: certified key ──────────────────────────────────────────────

    private const string PassWithKey =
        """
        {
          "verdict": { "device": { "ueid": "dev_1", "verdict": "pass" } },
          "assuranceClaimsMet": [],
          "enrollmentRequired": false,
          "key": {
            "keyId": "key_1",
            "jwk": { "kty": "EC", "crv": "P-256", "x": "eA", "y": "eQ" },
            "purpose": "sign",
            "authPolicy": "cG9saWN5",
            "certifiedAt": "2026-09-07T10:00:00.1234567+00:00"
          }
        }
        """;

    [Fact]
    public async Task VerifyAsync_parses_the_certified_key_from_the_response_root()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK, PassWithKey);

        var result = await client.VerifyAsync(new JsonObject(), new AttestOptions { ChallengeId = "chal_1" });

        Assert.True(result.IsAllowed);
        Assert.Equal("dev_1", result.DeviceId);
        var key = Assert.IsType<CertifiedKey>(result.Key);
        Assert.Equal("key_1", key.KeyId);
        Assert.Equal("sign", key.Purpose);
        Assert.Equal("cG9saWN5", key.AuthPolicy);
        Assert.Equal("EC", key.Jwk["kty"]?.GetValue<string>());
        Assert.Equal("P-256", key.Jwk["crv"]?.GetValue<string>());
        Assert.Equal("eA", key.Jwk["x"]?.GetValue<string>());
        Assert.Equal("eQ", key.Jwk["y"]?.GetValue<string>());
        Assert.Equal(new DateTimeOffset(2026, 9, 7, 10, 0, 0, TimeSpan.Zero).AddTicks(1234567), key.CertifiedAt);
        // The key is a sibling of the verdict, not part of it.
        Assert.Null(result.VerdictData["key"]);
    }

    [Fact]
    public async Task VerifyAsync_key_is_null_when_absent_or_beside_a_failing_verdict()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK, """{"verdict":{"device":{"verdict":"pass"}}}""");
        handler.Enqueue(HttpStatusCode.OK,
            """
            {
              "verdict": { "device": { "verdict": "fail" } },
              "key": { "keyId": "key_1", "jwk": { "kty": "EC", "crv": "P-256", "x": "eA", "y": "eQ" },
                       "purpose": "sign", "certifiedAt": "2026-09-07T10:00:00Z" }
            }
            """);

        var absent = await client.VerifyAsync(new JsonObject(), new AttestOptions { ChallengeId = "chal_1" });
        Assert.Null(absent.Key);
        Assert.Null(absent.DeviceId);

        var failed = await client.VerifyAsync(new JsonObject(), new AttestOptions { ChallengeId = "chal_1" });
        Assert.Equal("deny", failed.Verdict);
        Assert.Null(failed.Key);
    }

    [Fact]
    public async Task VerifyAsync_rejects_an_incomplete_key()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.OK,
            """{"verdict":{"device":{"verdict":"pass"}},"key":{"keyId":"key_1","purpose":"sign"}}""");

        await Assert.ThrowsAsync<RootHeraldApiException>(() =>
            client.VerifyAsync(new JsonObject(), new AttestOptions { ChallengeId = "chal_1" }));
    }

    // ── 422 by error code ──────────────────────────────────────────────────

    [Theory]
    [InlineData("admission_refused", typeof(AdmissionRefusedException))]
    [InlineData("unknown_policy", typeof(UnknownPolicyException))]
    [InlineData(null, typeof(UnknownPolicyException))]
    public async Task A_422_is_told_apart_by_its_error_code(string? code, Type expected)
    {
        var (client, handler) = Make();
        var body = code is null
            ? """{"message":"detail"}"""
            : $$"""{"error":"{{code}}","message":"detail: {{code}}"}""";
        handler.Enqueue(HttpStatusCode.UnprocessableEntity, body);

        var ex = await Assert.ThrowsAsync(expected, () =>
            client.VerifyAsync(new JsonObject(), new AttestOptions { ChallengeId = "chal_1" }));
        var api = Assert.IsAssignableFrom<RootHeraldApiException>(ex);
        Assert.Equal(422, api.StatusCode);
        Assert.Equal(code, api.ErrorCode);
        Assert.StartsWith("detail", api.Message);
    }

    // ── RelayEnroll with a challenge ───────────────────────────────────────

    private static EnrollRequestBlob Blob() => new()
    {
        EkPublicKey = "ekpub",
        AkPublicArea = "akpub",
        Platform = "windows",
    };

    [Fact]
    public async Task RelayEnrollAsync_scopes_admission_to_the_challenge_via_the_query_string()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.Created,
            """{"deviceId":"dev_42","challengeId":"ch 1/&x","credentialBlob":"cred","encryptedSecret":"sec"}""");
        handler.Enqueue(HttpStatusCode.Created,
            """{"deviceId":"dev_42","credentialBlob":"cred","encryptedSecret":"sec"}""");

        var scoped = await client.RelayEnrollAsync(Blob(), "ch 1/&x");
        Assert.Equal("/api/v1/attest/enroll?challengeId=ch%201%2F%26x", handler.LastRequestPath);
        Assert.Equal("ch 1/&x", scoped.Challenge.ChallengeId);
        // The query string is not smuggled into the body.
        var body = Assert.IsType<JsonObject>(handler.LastBody);
        Assert.False(body.ContainsKey("challengeId"));

        var plain = await client.RelayEnrollAsync(Blob());
        Assert.Equal("/api/v1/attest/enroll", handler.LastRequestPath);
        Assert.Null(plain.Challenge.ChallengeId);
    }

    [Fact]
    public async Task RelayEnrollAsync_surfaces_admission_refused_with_the_class()
    {
        var (client, handler) = Make();
        handler.Enqueue(HttpStatusCode.UnprocessableEntity,
            """{"error":"admission_refused","message":"policy requires a discrete TPM; device class is firmware-tpm"}""");

        var ex = await Assert.ThrowsAsync<AdmissionRefusedException>(() => client.RelayEnrollAsync(Blob(), "chal_1"));

        Assert.Equal("admission_refused", ex.ErrorCode);
        Assert.Contains("firmware-tpm", ex.Message);
    }

    // ── VerifyKeySignature ─────────────────────────────────────────────────

    private static JsonObject JwkFor(ECDsa key, string crv)
    {
        var p = key.ExportParameters(false);
        return new JsonObject
        {
            ["kty"] = "EC",
            ["crv"] = crv,
            ["x"] = Base64Url(p.Q.X!),
            ["y"] = Base64Url(p.Q.Y!),
        };
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    [Theory]
    [InlineData("P-256", 64)]
    [InlineData("P-384", 96)]
    public void VerifyKeySignature_accepts_raw_and_der_signatures(string crv, int rawLength)
    {
        using var key = ECDsa.Create(crv == "P-256" ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384);
        var hash = crv == "P-256" ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA384;
        var jwk = JwkFor(key, crv);
        var message = Encoding.UTF8.GetBytes("""{"action":"transfer","amount":100}""");

        var raw = key.SignData(message, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var der = key.SignData(message, hash, DSASignatureFormat.Rfc3279DerSequence);

        Assert.Equal(rawLength, raw.Length);
        Assert.True(RootHeraldClient.VerifyKeySignature(jwk, message, raw));
        Assert.True(RootHeraldClient.VerifyKeySignature(jwk, message, der));

        // Padded base64url coordinates are tolerated.
        var padded = (JsonObject)jwk.DeepClone();
        padded["x"] = Convert.ToBase64String(key.ExportParameters(false).Q.X!).Replace('+', '-').Replace('/', '_');
        Assert.True(RootHeraldClient.VerifyKeySignature(padded, message, der));
    }

    [Fact]
    public void VerifyKeySignature_rejects_tampering_and_never_throws()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwk = JwkFor(key, "P-256");
        var message = Encoding.UTF8.GetBytes("original");
        var raw = key.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var der = key.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        Assert.False(RootHeraldClient.VerifyKeySignature(jwk, Encoding.UTF8.GetBytes("tampered"), raw));
        Assert.False(RootHeraldClient.VerifyKeySignature(jwk, Encoding.UTF8.GetBytes("tampered"), der));

        var flipped = (byte[])raw.Clone();
        flipped[10] ^= 0x01;
        Assert.False(RootHeraldClient.VerifyKeySignature(jwk, message, flipped));

        Assert.False(RootHeraldClient.VerifyKeySignature(JwkFor(other, "P-256"), message, der));

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
}
