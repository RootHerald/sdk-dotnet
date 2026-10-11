using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;

namespace RootHerald.AspNetCore.Tests;

/// <summary>
/// The envelope must be exactly what the device's whitelist parser opens:
/// one header shape, the header as AAD, a fresh ephemeral key per call; and
/// every key that cannot open it is refused before anything is encrypted.
/// </summary>
public class EncryptToDeviceTests
{
    private static readonly byte[] Plaintext = Encoding.UTF8.GetBytes("""{"session":"s-1","exp":1893456000}""");

    private static CertifiedKey Key(string purpose, string alg, string? format, JsonObject jwk) =>
        new("dev-alias", "key-1", purpose, alg, format, jwk, true, DateTimeOffset.UnixEpoch);

    private static (CertifiedKey key, ECDiffieHellman priv) EcDecryptKey()
    {
        var priv = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var q = priv.ExportParameters(false).Q;
        var jwk = new JsonObject
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = DeviceEnvelope.Base64Url(q.X!),
            ["y"] = DeviceEnvelope.Base64Url(q.Y!),
        };
        return (Key(KeyPurpose.Decrypt, "ECDH-ES", "jwe", jwk), priv);
    }

    private static (CertifiedKey key, RSA priv) RsaDecryptKey(int bits = 2048)
    {
        var priv = RSA.Create(bits);
        var p = priv.ExportParameters(false);
        var jwk = new JsonObject
        {
            ["kty"] = "RSA",
            ["n"] = DeviceEnvelope.Base64Url(p.Modulus!),
            ["e"] = DeviceEnvelope.Base64Url(p.Exponent!),
        };
        return (Key(KeyPurpose.Decrypt, "RSA-OAEP-256", "jwe", jwk), priv);
    }

    // ── ECDH-ES ────────────────────────────────────────────────────────────

    [Fact]
    public void Ec_key_two_encryptions_differ_and_both_open()
    {
        var (key, priv) = EcDecryptKey();
        var a = RootHeraldClient.EncryptToDevice(key, Plaintext);
        var b = RootHeraldClient.EncryptToDevice(key, Plaintext);

        Assert.NotEqual(a, b);
        Assert.Equal(Plaintext, ReferenceDecryptor.Open(a, priv));
        Assert.Equal(Plaintext, ReferenceDecryptor.Open(b, priv));
    }

    [Fact]
    public void Ec_header_is_exactly_alg_enc_epk()
    {
        var (key, _) = EcDecryptKey();
        var header = ReferenceDecryptor.Header(RootHeraldClient.EncryptToDevice(key, Plaintext));

        Assert.Equal(new[] { "alg", "enc", "epk" }, header.Select(p => p.Key).ToArray());
        Assert.Equal("ECDH-ES", header["alg"]!.GetValue<string>());
        Assert.Equal("A256GCM", header["enc"]!.GetValue<string>());
        var epk = header["epk"]!.AsObject();
        Assert.Equal(new[] { "kty", "crv", "x", "y" }, epk.Select(p => p.Key).ToArray());
        Assert.Equal("EC", epk["kty"]!.GetValue<string>());
        Assert.Equal("P-256", epk["crv"]!.GetValue<string>());
        Assert.Equal(32, ReferenceDecryptor.Decode(epk["x"]!.GetValue<string>()).Length);
        Assert.Equal(32, ReferenceDecryptor.Decode(epk["y"]!.GetValue<string>()).Length);
    }

    [Fact]
    public void Ec_encrypted_key_segment_is_empty_iv_12_tag_16()
    {
        var (key, _) = EcDecryptKey();
        var parts = RootHeraldClient.EncryptToDevice(key, Plaintext).Split('.');

        Assert.Equal(5, parts.Length);
        Assert.Equal("", parts[1]);
        Assert.Equal(12, ReferenceDecryptor.Decode(parts[2]).Length);
        Assert.Equal(Plaintext.Length, ReferenceDecryptor.Decode(parts[3]).Length);
        Assert.Equal(16, ReferenceDecryptor.Decode(parts[4]).Length);
    }

    [Fact]
    public void Ec_epk_coordinates_are_left_padded_to_32_bytes()
    {
        var (key, priv) = EcDecryptKey();
        // An ephemeral key whose X has a leading zero byte: the header must
        // still carry 32-byte coordinates, or the device refuses the epk.
        ECDiffieHellman shortX;
        while (true)
        {
            shortX = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            if (shortX.ExportParameters(false).Q.X![0] == 0) break;
            shortX.Dispose();
        }
        var jwe = RootHeraldClient.EncryptToDevice(key, Plaintext, () => shortX, DeviceEnvelope.RandomBytes);
        var epk = ReferenceDecryptor.Header(jwe)["epk"]!.AsObject();

        Assert.Equal(32, ReferenceDecryptor.Decode(epk["x"]!.GetValue<string>()).Length);
        Assert.Equal(Plaintext, ReferenceDecryptor.Open(jwe, priv));
    }

    // ── RSA-OAEP-256 ───────────────────────────────────────────────────────

    [Fact]
    public void Rsa_key_two_encryptions_differ_and_both_open()
    {
        var (key, priv) = RsaDecryptKey();
        var a = RootHeraldClient.EncryptToDevice(key, Plaintext);
        var b = RootHeraldClient.EncryptToDevice(key, Plaintext);

        Assert.NotEqual(a, b);
        Assert.Equal(Plaintext, ReferenceDecryptor.Open(a, priv));
        Assert.Equal(Plaintext, ReferenceDecryptor.Open(b, priv));
    }

    [Fact]
    public void Rsa_header_is_exactly_alg_enc_and_key_segment_is_modulus_length()
    {
        var (key, _) = RsaDecryptKey();
        var jwe = RootHeraldClient.EncryptToDevice(key, Plaintext);
        var header = ReferenceDecryptor.Header(jwe);

        Assert.Equal(new[] { "alg", "enc" }, header.Select(p => p.Key).ToArray());
        Assert.Equal("RSA-OAEP-256", header["alg"]!.GetValue<string>());
        Assert.Equal("A256GCM", header["enc"]!.GetValue<string>());
        Assert.Equal(256, ReferenceDecryptor.Decode(jwe.Split('.')[1]).Length);
    }

    [Fact]
    public void Rsa_wraps_with_oaep_sha256_and_mgf1_sha256()
    {
        var (key, priv) = RsaDecryptKey();
        var jwe = RootHeraldClient.EncryptToDevice(key, Plaintext);
        var encryptedKey = ReferenceDecryptor.Decode(jwe.Split('.')[1]);

        Assert.Equal(32, priv.Decrypt(encryptedKey, RSAEncryptionPadding.OaepSHA256).Length);
        Assert.ThrowsAny<CryptographicException>(() => priv.Decrypt(encryptedKey, RSAEncryptionPadding.OaepSHA1));
    }

    // ── AAD is the protected header ────────────────────────────────────────

    [Theory]
    [InlineData("EC")]
    [InlineData("RSA")]
    public void A_header_edited_after_sealing_does_not_open(string kty)
    {
        CertifiedKey key;
        AsymmetricAlgorithm priv;
        if (kty == "EC") (key, priv) = EcDecryptKey(); else (key, priv) = RsaDecryptKey();
        var parts = RootHeraldClient.EncryptToDevice(key, Plaintext).Split('.');
        // Re-encode the same header with one byte of whitespace: the JSON is
        // equivalent, the AAD is not.
        var json = Encoding.UTF8.GetString(ReferenceDecryptor.Decode(parts[0]));
        parts[0] = DeviceEnvelope.Base64Url(Encoding.UTF8.GetBytes(json.Replace("\"enc\":", "\"enc\": ")));

        Assert.ThrowsAny<CryptographicException>(() => ReferenceDecryptor.Open(string.Join('.', parts), priv, strictHeader: false));
    }

    // ── Refusals ───────────────────────────────────────────────────────────

    [Fact]
    public void A_sign_key_is_refused()
    {
        var (dec, _) = EcDecryptKey();
        var sign = dec with { Purpose = KeyPurpose.Sign, Alg = "ES256", Format = null };
        var signWithJweFormat = dec with { Purpose = KeyPurpose.Sign, Alg = "ES256" };
        var decryptPurposeSignAlg = dec with { Alg = "ES256" };

        Assert.Throws<ArgumentException>(() => RootHeraldClient.EncryptToDevice(sign, Plaintext));
        Assert.Throws<ArgumentException>(() => RootHeraldClient.EncryptToDevice(signWithJweFormat, Plaintext));
        Assert.Throws<ArgumentException>(() => RootHeraldClient.EncryptToDevice(decryptPurposeSignAlg, Plaintext));
    }

    [Fact]
    public void An_apple_ecies_key_is_refused_by_name()
    {
        var (dec, _) = EcDecryptKey();
        var apple = dec with { Format = "apple-ecies", HardwareBound = false };

        var ex = Assert.Throws<EnvelopeFormatNotSupportedException>(() => RootHeraldClient.EncryptToDevice(apple, Plaintext));
        Assert.Equal("apple-ecies", ex.Format);
        Assert.Contains("apple-ecies", ex.Message);
        Assert.IsAssignableFrom<ArgumentException>(ex);
    }

    [Fact]
    public void A_decrypt_key_without_a_format_is_refused()
    {
        var (dec, _) = EcDecryptKey();
        Assert.Throws<ArgumentException>(() => RootHeraldClient.EncryptToDevice(dec with { Format = null }, Plaintext));
    }

    [Fact]
    public void A_p384_key_is_refused()
    {
        using var p384 = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
        var q = p384.ExportParameters(false).Q;
        var jwk = new JsonObject
        {
            ["kty"] = "EC",
            ["crv"] = "P-384",
            ["x"] = DeviceEnvelope.Base64Url(q.X!),
            ["y"] = DeviceEnvelope.Base64Url(q.Y!),
        };
        var key = Key(KeyPurpose.Decrypt, "ECDH-ES", "jwe", jwk);

        Assert.Throws<ArgumentException>(() => RootHeraldClient.EncryptToDevice(key, Plaintext));
    }

    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    public void Ec_coordinates_that_are_not_32_bytes_are_refused(int length)
    {
        var (dec, _) = EcDecryptKey();
        var jwk = JsonNode.Parse(dec.Jwk.ToJsonString())!.AsObject();
        jwk["x"] = DeviceEnvelope.Base64Url(new byte[length]);

        Assert.Throws<ArgumentException>(() => RootHeraldClient.EncryptToDevice(dec with { Jwk = jwk }, Plaintext));
    }

    [Fact]
    public void An_ec_point_off_the_curve_is_refused()
    {
        var (dec, _) = EcDecryptKey();
        var jwk = JsonNode.Parse(dec.Jwk.ToJsonString())!.AsObject();
        var y = ReferenceDecryptor.Decode(jwk["y"]!.GetValue<string>());
        y[31] ^= 0x01;
        jwk["y"] = DeviceEnvelope.Base64Url(y);

        Assert.Throws<ArgumentException>(() => RootHeraldClient.EncryptToDevice(dec with { Jwk = jwk }, Plaintext));
    }

    [Fact]
    public void An_ec_coordinate_at_or_above_the_field_prime_is_refused()
    {
        var (dec, _) = EcDecryptKey();
        var jwk = JsonNode.Parse(dec.Jwk.ToJsonString())!.AsObject();
        jwk["x"] = DeviceEnvelope.Base64Url(Enumerable.Repeat((byte)0xff, 32).ToArray());

        Assert.Throws<ArgumentException>(() => RootHeraldClient.EncryptToDevice(dec with { Jwk = jwk }, Plaintext));
    }

    [Fact]
    public void A_short_rsa_modulus_is_refused()
    {
        var (key, _) = RsaDecryptKey(1024);
        Assert.Throws<ArgumentException>(() => RootHeraldClient.EncryptToDevice(key, Plaintext));
    }

    [Theory]
    [InlineData("AA")]
    [InlineData("AQ")]
    [InlineData("AAI")]
    public void An_rsa_exponent_below_3_is_refused(string e)
    {
        var (key, _) = RsaDecryptKey();
        var jwk = JsonNode.Parse(key.Jwk.ToJsonString())!.AsObject();
        jwk["e"] = e;

        Assert.Throws<ArgumentException>(() => RootHeraldClient.EncryptToDevice(key with { Jwk = jwk }, Plaintext));
    }

    [Fact]
    public void A_mismatched_alg_and_kty_is_refused()
    {
        var (ec, _) = EcDecryptKey();
        var (rsa, _) = RsaDecryptKey();

        Assert.Throws<ArgumentException>(() => RootHeraldClient.EncryptToDevice(ec with { Alg = "RSA-OAEP-256" }, Plaintext));
        Assert.Throws<ArgumentException>(() => RootHeraldClient.EncryptToDevice(rsa with { Alg = "ECDH-ES" }, Plaintext));
    }

    // ── Determinism through the seam ───────────────────────────────────────

    [Fact]
    public void The_seam_makes_the_envelope_reproducible()
    {
        var (key, priv) = EcDecryptKey();
        using var eph = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var ephParams = eph.ExportParameters(true);
        byte[] Fixed(int n) => Enumerable.Range(1, n).Select(i => (byte)i).ToArray();

        var a = RootHeraldClient.EncryptToDevice(key, Plaintext, () => ECDiffieHellman.Create(ephParams), Fixed);
        var b = RootHeraldClient.EncryptToDevice(key, Plaintext, () => ECDiffieHellman.Create(ephParams), Fixed);

        Assert.Equal(a, b);
        Assert.Equal(Plaintext, ReferenceDecryptor.Open(a, priv));
    }

    // ── Known-answer vectors from platform Fixtures/envelope ───────────────
    //
    // ECDH-ES replays byte for byte with the vector's ephemeral key and IV.
    // RSA-OAEP-256 draws its OAEP seed inside RSA.Encrypt, so the header, IV,
    // ciphertext and tag are byte-equal and the encrypted key must unwrap to
    // the vector's CEK.

    private static JsonObject Vector(string file) =>
        JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "envelope", file)))!.AsObject();

    private static byte[] Bytes(JsonObject v, string field) => ReferenceDecryptor.Decode(v[field]!.GetValue<string>());

    private static JsonObject PublicJwk(JsonObject privateJwk)
    {
        var kty = privateJwk["kty"]!.GetValue<string>();
        var jwk = new JsonObject { ["kty"] = kty };
        foreach (var field in kty == "EC" ? new[] { "crv", "x", "y" } : new[] { "n", "e" })
            jwk[field] = privateJwk[field]!.GetValue<string>();
        return jwk;
    }

    [Fact]
    public void EcdhEs_vector_replays_byte_for_byte()
    {
        var v = Vector("ecdh-es-a256gcm.json");
        var eph = v["ephemeral"]!.AsObject();
        var ephParams = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = Bytes(eph, "d"),
            Q = new ECPoint { X = Bytes(eph, "x"), Y = Bytes(eph, "y") },
        };
        var key = Key(KeyPurpose.Decrypt, "ECDH-ES", "jwe", PublicJwk(v["recipient"]!.AsObject()));

        var jwe = RootHeraldClient.EncryptToDevice(key, Bytes(v, "plaintext"), () => ECDiffieHellman.Create(ephParams),
            n => n == 12 ? Bytes(v, "iv") : throw new InvalidOperationException($"ECDH-ES drew {n} random bytes"));

        Assert.Equal(v["jwe"]!.GetValue<string>(), jwe);
    }

    [Fact]
    public void RsaOaep256_vector_replays_except_the_oaep_seed()
    {
        var v = Vector("rsa-oaep-256-a256gcm.json");
        var r = v["recipient"]!.AsObject();
        var key = Key(KeyPurpose.Decrypt, "RSA-OAEP-256", "jwe", PublicJwk(r));

        var jwe = RootHeraldClient.EncryptToDevice(key, Bytes(v, "plaintext"), () => throw new InvalidOperationException("RSA drew an ephemeral key"),
            n => n switch { 32 => Bytes(v, "cek"), 12 => Bytes(v, "iv"), _ => throw new InvalidOperationException($"drew {n} random bytes") });

        var expected = v["jwe"]!.GetValue<string>().Split('.');
        var actual = jwe.Split('.');
        Assert.Equal(expected[0], actual[0]);
        Assert.Equal(expected[2], actual[2]);
        Assert.Equal(expected[3], actual[3]);
        Assert.Equal(expected[4], actual[4]);
        using var rsa = RSA.Create(new RSAParameters
        {
            Modulus = Bytes(r, "n"),
            Exponent = Bytes(r, "e"),
            D = Bytes(r, "d"),
            P = Bytes(r, "p"),
            Q = Bytes(r, "q"),
            DP = Bytes(r, "dp"),
            DQ = Bytes(r, "dq"),
            InverseQ = Bytes(r, "qi"),
        });
        Assert.Equal(Bytes(v, "cek"), rsa.Decrypt(ReferenceDecryptor.Decode(actual[1]), RSAEncryptionPadding.OaepSHA256));
    }
}

/// <summary>
/// The device's parser, in software: a whitelist over the header, fixed
/// sizes, the header as AAD, and the same Concat KDF.
/// </summary>
internal static class ReferenceDecryptor
{
    public static byte[] Open(string compact, AsymmetricAlgorithm recipient, bool strictHeader = true)
    {
        var parts = compact.Split('.');
        if (parts.Length != 5) throw new FormatException("not a five-segment compact JWE");
        var header = Header(compact);
        var iv = Decode(parts[2]);
        var ciphertext = Decode(parts[3]);
        var tag = Decode(parts[4]);
        if (iv.Length != 12 || tag.Length != 16) throw new FormatException("iv/tag size");
        if (header["enc"]!.GetValue<string>() != "A256GCM") throw new FormatException("enc");

        byte[] cek;
        switch (recipient)
        {
            case ECDiffieHellman ec:
                if (strictHeader) RequireKeys(header, "alg", "enc", "epk");
                if (header["alg"]!.GetValue<string>() != "ECDH-ES") throw new FormatException("alg");
                if (parts[1].Length != 0) throw new FormatException("encrypted key present on ECDH-ES");
                var epk = header["epk"]!.AsObject();
                if (strictHeader) RequireKeys(epk, "kty", "crv", "x", "y");
                if (epk["kty"]!.GetValue<string>() != "EC" || epk["crv"]!.GetValue<string>() != "P-256") throw new FormatException("epk");
                var x = Decode(epk["x"]!.GetValue<string>());
                var y = Decode(epk["y"]!.GetValue<string>());
                if (x.Length != 32 || y.Length != 32) throw new FormatException("epk coordinate size");
                using (var ephPub = ECDiffieHellman.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } }))
                {
                    var z = ec.DeriveRawSecretAgreement(ephPub.PublicKey);
                    cek = ConcatKdf(z);
                }
                break;
            case RSA rsa:
                if (strictHeader) RequireKeys(header, "alg", "enc");
                if (header["alg"]!.GetValue<string>() != "RSA-OAEP-256") throw new FormatException("alg");
                cek = rsa.Decrypt(Decode(parts[1]), RSAEncryptionPadding.OaepSHA256);
                break;
            default:
                throw new ArgumentException("recipient");
        }

        var plaintext = new byte[ciphertext.Length];
        using var gcm = new AesGcm(cek, 16);
        gcm.Decrypt(iv, ciphertext, tag, plaintext, Encoding.ASCII.GetBytes(parts[0]));
        return plaintext;
    }

    public static JsonObject Header(string compact) =>
        JsonNode.Parse(Decode(compact.Split('.')[0]), documentOptions: new JsonDocumentOptions { AllowTrailingCommas = false })!.AsObject();

    private static void RequireKeys(JsonObject obj, params string[] keys)
    {
        var actual = obj.Select(p => p.Key).ToArray();
        if (!actual.SequenceEqual(keys)) throw new FormatException($"header members {string.Join(",", actual)}");
    }

    public static byte[] ConcatKdf(byte[] z)
    {
        var alg = Encoding.ASCII.GetBytes("A256GCM");
        var input = new List<byte>();
        input.AddRange(new byte[] { 0, 0, 0, 1 });
        input.AddRange(z);
        input.AddRange(new byte[] { 0, 0, 0, (byte)alg.Length });
        input.AddRange(alg);
        input.AddRange(new byte[] { 0, 0, 0, 0 });
        input.AddRange(new byte[] { 0, 0, 0, 0 });
        input.AddRange(new byte[] { 0, 0, 1, 0 });
        return SHA256.HashData(input.ToArray());
    }

    public static byte[] Decode(string value)
    {
        var s = value.Replace('-', '+').Replace('_', '/');
        s = s.PadRight(s.Length + (4 - s.Length % 4) % 4, '=');
        return Convert.FromBase64String(s);
    }
}
