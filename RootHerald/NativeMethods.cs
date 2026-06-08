using System.Runtime.InteropServices;

namespace RootHerald;

/// <summary>
/// Raw P/Invoke surface for RootHerald.dll. Matches the public C ABI
/// declared in <c>src/clients/common/rootherald.h</c>. Keep this in lockstep
/// with the header: any drift will manifest as silent corruption at the
/// ABI boundary.
/// </summary>
internal static class NativeMethods
{
    // The .NET native-loader maps this to the per-platform file
    // (RootHerald.dll / librootherald.so / librootherald.dylib).
    internal const string LibraryName = "RootHerald";

    internal const int ROOTHERALD_OK = 0;
    internal const int ROOTHERALD_ERR_INVALID_ARG = 1;
    internal const int ROOTHERALD_ERR_TPM_UNAVAILABLE = 2;
    internal const int ROOTHERALD_ERR_NETWORK = 3;
    internal const int ROOTHERALD_ERR_SERVER = 4;
    internal const int ROOTHERALD_ERR_QUOTA_EXCEEDED = 5;
    internal const int ROOTHERALD_ERR_INTERNAL = 99;

    internal const int ROOTHERALD_VERDICT_ALLOW = 0;
    internal const int ROOTHERALD_VERDICT_WARN = 1;
    internal const int ROOTHERALD_VERDICT_DENY = 2;

    // Matches RootHeraldVerifyResult in rootherald.h exactly:
    //   int verdict; char[129]; char[64]; char[1024]; char[256];
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal struct VerifyResultNative
    {
        public int Verdict;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)]
        public string DeviceId;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string TpmClass;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 1024)]
        public string PostureJson;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string Reason;
    }

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl,
               CharSet = CharSet.Ansi, EntryPoint = "RootHeraldClient_Create")]
    [return: MarshalAs(UnmanagedType.SysInt)]
    internal static extern IntPtr Create(
        [MarshalAs(UnmanagedType.LPStr)] string apiKey,
        [MarshalAs(UnmanagedType.LPStr)] string? endpoint);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl,
               EntryPoint = "RootHeraldClient_Destroy")]
    internal static extern void Destroy(IntPtr client);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl,
               CharSet = CharSet.Ansi, EntryPoint = "RootHeraldClient_SetEndpoint")]
    internal static extern int SetEndpoint(IntPtr client,
        [MarshalAs(UnmanagedType.LPStr)] string endpoint);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl,
               CharSet = CharSet.Ansi, EntryPoint = "RootHeraldClient_SetApplicationId")]
    internal static extern int SetApplicationId(IntPtr client,
        [MarshalAs(UnmanagedType.LPStr)] string appId);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl,
               EntryPoint = "RootHeraldClient_SetMockTpm")]
    internal static extern int SetMockTpm(IntPtr client, int mockEnabled);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl,
               CharSet = CharSet.Ansi, EntryPoint = "RootHeraldClient_Verify")]
    internal static extern int Verify(IntPtr client,
        [MarshalAs(UnmanagedType.LPStr)] string? action,
        out VerifyResultNative outResult);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl,
               EntryPoint = "RootHerald_AbiVersionString")]
    internal static extern IntPtr AbiVersionString();

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl,
               EntryPoint = "RootHerald_LibraryVersionString")]
    internal static extern IntPtr LibraryVersionString();
}
