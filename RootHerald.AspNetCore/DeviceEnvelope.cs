using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace RootHerald.AspNetCore;

/// <summary>
/// The key's <c>format</c> is one <see cref="RootHeraldClient.EncryptToDevice(CertifiedKey, ReadOnlySpan{byte})"/>
/// cannot produce: <c>apple-ecies</c>, the Security.framework ECIES envelope a
/// macOS enclave key opens, needs an Apple-side encryptor.
/// </summary>
public sealed class EnvelopeFormatNotSupportedException : ArgumentException
{
    /// <param name="format">The key's <c>format</c>.</param>
    /// <param name="paramName">The refused argument.</param>
    public EnvelopeFormatNotSupportedException(string format, string paramName)
        : base($"key format \"{format}\" is not produced here: EncryptToDevice writes the jwe envelope a TPM decrypt key opens; an apple-ecies key needs an Apple-side encryptor", paramName)
    {
        Format = format;
    }

    /// <summary>The key's <c>format</c>.</summary>
    public string Format { get; }
}

/// <summary>
/// The one JWE compact serialization a TPM decrypt key opens: ECDH-ES with
/// the Concat KDF (RFC 7518 §4.6, AlgorithmID = the enc name, PartyU and
/// PartyV empty, 256-bit key) for an EC P-256 key, RSA-OAEP-256 wrapping a
/// random 32-byte CEK for an RSA key, A256GCM for both. The protected header
/// carries alg, enc and (ECDH-ES only) epk, nothing else, because the device
/// refuses any other member rather than ignoring it.
/// </summary>
internal static class DeviceEnvelope
{
    internal const string AlgEcdhEs = "ECDH-ES";
    internal const string AlgRsaOaep256 = "RSA-OAEP-256";
    internal const string Enc = "A256GCM";
    internal const string FormatJwe = "jwe";
    private const int CoordinateBytes = 32;
    private const int IvBytes = 12;
    private const int TagBytes = 16;
    private const int CekBytes = 32;

    internal static string Encrypt(CertifiedKey key, ReadOnlySpan<byte> plaintext, Func<ECDiffieHellman> ephemeral, Func<int, byte[]> random)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Purpose != KeyPurpose.Decrypt)
            throw new ArgumentException($"key purpose is \"{key.Purpose}\"; only a decrypt key opens an envelope", nameof(key));
        if (key.Format != FormatJwe)
        {
            if (key.Format is null)
                throw new ArgumentException("key has no envelope format; a decrypt key names jwe or apple-ecies", nameof(key));
            throw new EnvelopeFormatNotSupportedException(key.Format, nameof(key));
        }
        if (key.Jwk is null)
            throw new ArgumentException("key has no jwk", nameof(key));

        var kty = ReadString(key.Jwk["kty"]);
        return (kty, key.Alg) switch
        {
            ("EC", AlgEcdhEs) => EncryptEcdhEs(key.Jwk, plaintext, ephemeral, random),
            ("RSA", AlgRsaOaep256) => EncryptRsaOaep(key.Jwk, plaintext, random),
            _ => throw new ArgumentException($"key alg \"{key.Alg}\" with kty \"{kty}\" is not ECDH-ES on an EC key or RSA-OAEP-256 on an RSA key", nameof(key)),
        };
    }

    private static string EncryptEcdhEs(JsonObject jwk, ReadOnlySpan<byte> plaintext, Func<ECDiffieHellman> ephemeral, Func<int, byte[]> random)
    {
        if (ReadString(jwk["crv"]) != "P-256")
            throw new ArgumentException($"jwk.crv \"{ReadString(jwk["crv"])}\" is not P-256; no device certifies another curve", nameof(jwk));
        var x = DecodeCoordinate(jwk, "x");
        var y = DecodeCoordinate(jwk, "y");
        if (!IsOnP256(x, y))
            throw new ArgumentException("jwk.x and jwk.y are not a point on P-256", nameof(jwk));

        using var recipient = ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = x, Y = y },
        });
        using var eph = ephemeral();
        var z = eph.DeriveRawSecretAgreement(recipient.PublicKey);
        var cek = ConcatKdf(z);
        CryptographicOperations.ZeroMemory(z);

        var epk = eph.ExportParameters(false).Q;
        var header = $"{{\"alg\":\"{AlgEcdhEs}\",\"enc\":\"{Enc}\",\"epk\":{{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{Base64Url(LeftPad(epk.X!, CoordinateBytes))}\",\"y\":\"{Base64Url(LeftPad(epk.Y!, CoordinateBytes))}\"}}}}";
        return Seal(header, Array.Empty<byte>(), cek, plaintext, random);
    }

    private static string EncryptRsaOaep(JsonObject jwk, ReadOnlySpan<byte> plaintext, Func<int, byte[]> random)
    {
        var n = DecodeBase64Url(ReadString(jwk["n"])) ?? throw new ArgumentException("jwk.n is required", nameof(jwk));
        var e = DecodeBase64Url(ReadString(jwk["e"])) ?? throw new ArgumentException("jwk.e is required", nameof(jwk));
        if (e.Length == 0 || n.Length < RootHeraldClient.MinRsaModulusBytes || (n[0] & 0x80) == 0)
            throw new ArgumentException("jwk.n must be a modulus of at least 2048 bits", nameof(jwk));
        if (new BigInteger(e, isUnsigned: true, isBigEndian: true) < 3)
            throw new ArgumentException("jwk.e must be at least 3", nameof(jwk));

        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters { Modulus = n, Exponent = e });
        var cek = random(CekBytes);
        var encryptedKey = rsa.Encrypt(cek, RSAEncryptionPadding.OaepSHA256);
        var header = $"{{\"alg\":\"{AlgRsaOaep256}\",\"enc\":\"{Enc}\"}}";
        return Seal(header, encryptedKey, cek, plaintext, random);
    }

    private static string Seal(string header, byte[] encryptedKey, byte[] cek, ReadOnlySpan<byte> plaintext, Func<int, byte[]> random)
    {
        var protectedHeader = Base64Url(Encoding.UTF8.GetBytes(header));
        var aad = Encoding.ASCII.GetBytes(protectedHeader);
        var iv = random(IvBytes);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagBytes];
        using (var gcm = new AesGcm(cek, TagBytes))
        {
            gcm.Encrypt(iv, plaintext, ciphertext, tag, aad);
        }
        CryptographicOperations.ZeroMemory(cek);
        return string.Join('.', protectedHeader, Base64Url(encryptedKey), Base64Url(iv), Base64Url(ciphertext), Base64Url(tag));
    }

    /// <summary>
    /// Concat KDF, one round: SHA-256(counter ‖ Z ‖ AlgorithmID ‖ PartyUInfo ‖
    /// PartyVInfo ‖ SuppPubInfo), each info field length-prefixed, keydatalen 256.
    /// </summary>
    private static byte[] ConcatKdf(byte[] z)
    {
        var alg = Encoding.ASCII.GetBytes(Enc);
        var input = new byte[4 + z.Length + 4 + alg.Length + 4 + 4 + 4];
        var o = 0;
        WriteUInt32(input, ref o, 1);
        z.CopyTo(input, o); o += z.Length;
        WriteUInt32(input, ref o, (uint)alg.Length);
        alg.CopyTo(input, o); o += alg.Length;
        WriteUInt32(input, ref o, 0);
        WriteUInt32(input, ref o, 0);
        WriteUInt32(input, ref o, 256);
        return SHA256.HashData(input);
    }

    private static void WriteUInt32(byte[] buffer, ref int offset, uint value)
    {
        buffer[offset++] = (byte)(value >> 24);
        buffer[offset++] = (byte)(value >> 16);
        buffer[offset++] = (byte)(value >> 8);
        buffer[offset++] = (byte)value;
    }

    private static byte[] DecodeCoordinate(JsonObject jwk, string field)
    {
        var raw = DecodeBase64Url(ReadString(jwk[field]));
        if (raw is not { Length: CoordinateBytes })
            throw new ArgumentException($"jwk.{field} must decode to exactly {CoordinateBytes} bytes", nameof(jwk));
        return raw;
    }

    private static readonly BigInteger P256Prime = BigInteger.Parse("0ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", System.Globalization.NumberStyles.HexNumber);
    private static readonly BigInteger P256B = BigInteger.Parse("05ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", System.Globalization.NumberStyles.HexNumber);

    // Checked in software because the OS import refuses an off-curve point
    // with a platform-dependent exception type.
    private static bool IsOnP256(byte[] xBytes, byte[] yBytes)
    {
        var x = new BigInteger(xBytes, isUnsigned: true, isBigEndian: true);
        var y = new BigInteger(yBytes, isUnsigned: true, isBigEndian: true);
        if (x >= P256Prime || y >= P256Prime) return false;
        var p = P256Prime;
        var lhs = y * y % p;
        var rhs = ((x * x % p * x - 3 * x + P256B) % p + p) % p;
        return lhs == rhs;
    }

    private static byte[] LeftPad(byte[] value, int length)
    {
        if (value.Length == length) return value;
        if (value.Length > length) throw new CryptographicException("coordinate longer than the curve width");
        var padded = new byte[length];
        value.CopyTo(padded, length - value.Length);
        return padded;
    }

    internal static byte[] RandomBytes(int count) => RandomNumberGenerator.GetBytes(count);

    internal static ECDiffieHellman FreshEphemeral() => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

    internal static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[]? DecodeBase64Url(string? value)
    {
        if (string.IsNullOrEmpty(value)) return null;
        var s = value.TrimEnd('=').Replace('-', '+').Replace('_', '/');
        s = s.PadRight(s.Length + (4 - s.Length % 4) % 4, '=');
        try
        {
            return Convert.FromBase64String(s);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static string? ReadString(JsonNode? node) =>
        node is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;
}
