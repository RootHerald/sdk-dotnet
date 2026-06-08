using System.Runtime.InteropServices;

namespace RootHerald;

/// <summary>
/// Verdict from <see cref="RootHeraldClient.VerifyAsync"/>.
/// </summary>
public enum RootHeraldVerdict
{
    /// <summary>Allow the action.</summary>
    Allow = 0,
    /// <summary>Allow but surface a warning to the user.</summary>
    Warn = 1,
    /// <summary>Reject the action.</summary>
    Deny = 2
}

/// <summary>
/// Result of a verify call. Immutable record returned to the caller after
/// the native ABI struct has been marshalled.
/// </summary>
public sealed record RootHeraldVerifyResult(
    RootHeraldVerdict Verdict,
    string DeviceId,
    string TpmClass,
    string PostureJson,
    string Reason);

/// <summary>
/// Raised when the native ABI returns a non-OK status.
/// </summary>
public sealed class RootHeraldException : Exception
{
    /// <summary>The native ABI status code.</summary>
    public int NativeStatus { get; }

    internal RootHeraldException(int nativeStatus, string message)
        : base(message)
    {
        NativeStatus = nativeStatus;
    }
}

/// <summary>
/// Idiomatic .NET wrapper over RootHerald.dll. The native ABI is sync, so
/// <see cref="VerifyAsync"/> dispatches through <c>Task.Run</c> to
/// keep the calling thread unblocked. Implements <see cref="IDisposable"/>
/// so the native handle is always released.
///
/// Transport modes are selected purely by the endpoint URL — see
/// <c>rootherald.h</c> for the contract.
/// </summary>
public sealed class RootHeraldClient : IDisposable
{
    private IntPtr _handle;
    private bool _disposed;

    /// <summary>
    /// Create a client. <paramref name="endpoint"/> may be <c>null</c> to use
    /// the default <c>https://rootherald.io</c>; pass a custom domain
    /// (<c>https://attest.yourapp.com</c>) or a reverse-proxy URL
    /// (<c>https://api.yourapp.com/rh-proxy</c>) for the other transport modes.
    /// </summary>
    public RootHeraldClient(string apiKey, string? endpoint = null)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
            throw new ArgumentException("apiKey is required.", nameof(apiKey));

        _handle = NativeMethods.Create(apiKey, endpoint);
        if (_handle == IntPtr.Zero)
            throw new RootHeraldException(NativeMethods.ROOTHERALD_ERR_INVALID_ARG,
                "Failed to create RootHeraldClient (native returned NULL).");
    }

    /// <summary>The ABI version implemented by the native library.</summary>
    public static string AbiVersion =>
        Marshal.PtrToStringAnsi(NativeMethods.AbiVersionString()) ?? "unknown";

    /// <summary>The library build version (semver) of the loaded native binary.</summary>
    public static string LibraryVersion =>
        Marshal.PtrToStringAnsi(NativeMethods.LibraryVersionString()) ?? "unknown";

    /// <summary>
    /// Switch to a different endpoint at runtime (e.g. failover from direct to
    /// custom-domain). The library treats every endpoint the same way — the
    /// URL selects the deployment mode transparently.
    /// </summary>
    public void SetEndpoint(string endpoint)
    {
        ThrowIfDisposed();
        var status = NativeMethods.SetEndpoint(_handle, endpoint);
        ThrowIfFailed(status, "SetEndpoint failed.");
    }

    /// <summary>
    /// Associate this client with a logical application id (used in policies
    /// and audit logs).
    /// </summary>
    public void SetApplicationId(string applicationId)
    {
        ThrowIfDisposed();
        var status = NativeMethods.SetApplicationId(_handle, applicationId);
        ThrowIfFailed(status, "SetApplicationId failed.");
    }

    /// <summary>
    /// Enable mock-TPM mode (canned evidence; never enable in production).
    /// Intended for CI agents and headless build machines.
    /// </summary>
    public void SetMockTpm(bool enabled)
    {
        ThrowIfDisposed();
        var status = NativeMethods.SetMockTpm(_handle, enabled ? 1 : 0);
        ThrowIfFailed(status, "SetMockTpm failed.");
    }

    /// <summary>
    /// Collect a fresh attestation and ask the server for a verdict on the
    /// given <paramref name="action"/>. Marshals the native sync call onto a
    /// thread-pool worker so the caller's thread stays responsive.
    /// </summary>
    public Task<RootHeraldVerifyResult> VerifyAsync(string? action = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        return Task.Run(() => VerifyCore(action), cancellationToken);
    }

    private RootHeraldVerifyResult VerifyCore(string? action)
    {
        var status = NativeMethods.Verify(_handle, action, out var raw);
        if (status != NativeMethods.ROOTHERALD_OK)
        {
            throw new RootHeraldException(status,
                $"Verify failed (status={status}): {raw.Reason}");
        }
        return new RootHeraldVerifyResult(
            Verdict: (RootHeraldVerdict)raw.Verdict,
            DeviceId: raw.DeviceId ?? string.Empty,
            TpmClass: raw.TpmClass ?? string.Empty,
            PostureJson: raw.PostureJson ?? "{}",
            Reason: raw.Reason ?? string.Empty);
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(RootHeraldClient));
    }

    private static void ThrowIfFailed(int status, string message)
    {
        if (status != NativeMethods.ROOTHERALD_OK)
            throw new RootHeraldException(status, message);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_handle != IntPtr.Zero)
        {
            NativeMethods.Destroy(_handle);
            _handle = IntPtr.Zero;
        }
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer — last-ditch cleanup if the caller forgot Dispose.</summary>
    ~RootHeraldClient()
    {
        if (_handle != IntPtr.Zero)
        {
            NativeMethods.Destroy(_handle);
            _handle = IntPtr.Zero;
        }
    }
}
