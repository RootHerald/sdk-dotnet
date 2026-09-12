using System.Net;
using Xunit;

namespace RootHerald.AspNetCore.Tests;

/// <summary>
/// Regression guards for three defects that shipped to customers.
///
/// MED-20: the constructor mutated a caller-supplied HttpClient, setting
/// DefaultRequestHeaders["Authorization"] and BaseAddress on it. With
/// IHttpClientFactory or a typed/singleton client — the documented way to inject
/// one — that client is shared, so the rh_sk_ secret was attached to EVERY request
/// it made, including to third parties.
///
/// MED-19: no SDK validated that baseUrl is https, so a typo'd or http:// value
/// sent the full-privilege secret in cleartext.
/// </summary>
public class ClientHardeningTests
{
    private const string SecretKey = "rh_sk_test_abc123";

    [Fact]
    public void Constructor_DoesNotMutateTheCallersHttpClient_MED20()
    {
        var http = new HttpClient(new MockHttpMessageHandler());

        _ = new RootHeraldClient(SecretKey, "https://api.test.local", http);

        // The caller's client must come back exactly as they handed it over — no
        // Authorization header for their other requests to carry, no BaseAddress.
        Assert.False(http.DefaultRequestHeaders.Contains("Authorization"));
        Assert.Null(http.BaseAddress);
    }

    [Fact]
    public async Task Constructor_DoesNotHijackAnInjectedBaseAddress_MED20()
    {
        // The old code did `_http.BaseAddress ??= ...`, so an injected client that
        // already had a BaseAddress silently won and the secret plus the evidence
        // went to whatever host that was. Requests must go where baseUrl says.
        var handler = new MockHttpMessageHandler();
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://someone-elses-host.test/") };

        var client = new RootHeraldClient(SecretKey, "https://api.test.local", http);
        handler.Enqueue(HttpStatusCode.OK, """{"nonce":"bm9uY2U","challenge":"rhc1.bm9uY2U.e30","expiresAt":"2030-01-01T00:00:00Z"}""");

        await client.IssueChallengeAsync();

        Assert.NotNull(handler.LastRequestHost);
        Assert.Equal("api.test.local", handler.LastRequestHost);
    }

    [Fact]
    public async Task Requests_CarryTheSecretPerRequest_MED20()
    {
        var handler = new MockHttpMessageHandler();
        var http = new HttpClient(handler);
        var client = new RootHeraldClient(SecretKey, "https://api.test.local", http);
        handler.Enqueue(HttpStatusCode.OK, """{"nonce":"bm9uY2U","challenge":"rhc1.bm9uY2U.e30","expiresAt":"2030-01-01T00:00:00Z"}""");

        await client.IssueChallengeAsync();

        Assert.Equal($"Bearer {SecretKey}", handler.LastAuthorization);
    }

    [Theory]
    [InlineData("http://api.test.local")]        // plaintext — would leak the key
    [InlineData("ftp://api.test.local")]
    [InlineData("not-a-url")]
    public void Constructor_RejectsNonHttpsBaseUrl_MED19(string baseUrl)
    {
        var http = new HttpClient(new MockHttpMessageHandler());
        Assert.Throws<ArgumentException>(
            () => new RootHeraldClient(SecretKey, baseUrl, http));
    }

    [Theory]
    [InlineData("http://localhost:5000")]
    [InlineData("http://127.0.0.1:5000")]
    public void Constructor_StillAllowsLoopbackForLocalDev_MED19(string baseUrl)
    {
        var http = new HttpClient(new MockHttpMessageHandler());
        var client = new RootHeraldClient(SecretKey, baseUrl, http);
        Assert.NotNull(client);
    }

}
