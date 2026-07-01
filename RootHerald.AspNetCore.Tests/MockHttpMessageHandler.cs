using System.Net;
using System.Text.Json.Nodes;

namespace RootHerald.AspNetCore.Tests;

/// <summary>
/// A scripted <see cref="HttpMessageHandler"/> for unit-testing
/// <see cref="RootHeraldBackgroundCheckClient"/> without a real network. Returns a
/// queued response per request and records the last request (URI, Authorization
/// header, JSON body) for assertions.
/// </summary>
internal sealed class MockHttpMessageHandler : HttpMessageHandler
{
    private readonly Queue<HttpResponseMessage> _responses = new();

    /// <summary>The path + query of the most recent request.</summary>
    public string? LastRequestPath { get; private set; }

    /// <summary>The <c>Authorization</c> header of the most recent request.</summary>
    public string? LastAuthorization { get; private set; }

    /// <summary>The parsed JSON body of the most recent request.</summary>
    public JsonNode? LastBody { get; private set; }

    /// <summary>Number of requests dispatched through this handler.</summary>
    public int RequestCount { get; private set; }

    public MockHttpMessageHandler Enqueue(HttpStatusCode status, string json)
    {
        _responses.Enqueue(new HttpResponseMessage(status)
        {
            Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json"),
        });
        return this;
    }

    /// <summary>Enqueue a non-JSON body (to exercise tolerant error parsing).</summary>
    public MockHttpMessageHandler EnqueueRaw(HttpStatusCode status, string body)
    {
        _responses.Enqueue(new HttpResponseMessage(status)
        {
            Content = new StringContent(body, System.Text.Encoding.UTF8, "text/plain"),
        });
        return this;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        RequestCount++;
        LastRequestPath = request.RequestUri?.PathAndQuery;
        LastAuthorization = request.Headers.Authorization?.ToString();
        if (request.Content is not null)
        {
            var raw = await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            LastBody = string.IsNullOrEmpty(raw) ? null : JsonNode.Parse(raw);
        }

        return _responses.Count > 0
            ? _responses.Dequeue()
            : new HttpResponseMessage(HttpStatusCode.InternalServerError)
            {
                Content = new StringContent("no scripted response", System.Text.Encoding.UTF8, "text/plain"),
            };
    }
}
