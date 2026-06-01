using RootHerald;

// Console sample showing the .NET wrapper end-to-end. Requires
// RootHerald.dll to be present on the loader path (usually next to the
// resulting exe). Use --mock to run without a TPM.

bool mock = args.Contains("--mock");
string apiKey = Environment.GetEnvironmentVariable("ROOTHERALD_API_KEY") ?? "rh_pk_test_demo";
string? endpoint = Environment.GetEnvironmentVariable("ROOTHERALD_ENDPOINT");

Console.WriteLine($"Root Herald .NET sample");
Console.WriteLine($"  ABI version    : {RootHeraldClient.AbiVersion}");
Console.WriteLine($"  Library version: {RootHeraldClient.LibraryVersion}");
Console.WriteLine($"  Endpoint       : {endpoint ?? "(default)"}");
Console.WriteLine($"  Mock TPM       : {mock}");
Console.WriteLine();

await using var client = new AsyncDisposableWrapper(new RootHeraldClient(apiKey, endpoint));
if (mock) client.Inner.SetMockTpm(true);

client.Inner.SetApplicationId("rootherald.sample.console");

try
{
    var result = await client.Inner.VerifyAsync("sample-launch");
    Console.WriteLine($"Verdict   : {result.Verdict}");
    Console.WriteLine($"Device id : {result.DeviceId}");
    Console.WriteLine($"TPM class : {result.TpmClass}");
    Console.WriteLine($"Reason    : {result.Reason}");
}
catch (RootHeraldException ex)
{
    Console.Error.WriteLine($"Attestation failed (status={ex.NativeStatus}): {ex.Message}");
    return 1;
}

return 0;

// Tiny helper to bridge sync IDisposable to await using.
internal sealed class AsyncDisposableWrapper(RootHeraldClient inner) : IAsyncDisposable
{
    public RootHeraldClient Inner { get; } = inner;
    public ValueTask DisposeAsync()
    {
        Inner.Dispose();
        return ValueTask.CompletedTask;
    }
}
