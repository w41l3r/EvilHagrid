using System.ComponentModel;
using System.Runtime.InteropServices;
using EvilHagrid.Domain;

namespace EvilHagrid.Ministry;

internal sealed class MinistryLedger
{
    private const int KerbQueryTicketCacheExMessage = 14;
    private const uint MaximumTicketCount = 100_000;

    public IReadOnlyList<ScrollRecord> ReadCurrentSession(string? serviceFilter)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Kerberos cache inspection is available on Windows only; no action was performed.");
        }

        var lsaHandle = IntPtr.Zero;
        var packageBuffer = IntPtr.Zero;
        var requestBuffer = IntPtr.Zero;
        var responseBuffer = IntPtr.Zero;

        try
        {
            ThrowForNtStatus(LsaConnectUntrusted(out lsaHandle), "LsaConnectUntrusted");

            packageBuffer = Marshal.StringToHGlobalAnsi("Kerberos");
            var packageName = new LsaString
            {
                Length = 8,
                MaximumLength = 9,
                Buffer = packageBuffer
            };

            ThrowForNtStatus(
                LsaLookupAuthenticationPackage(lsaHandle, ref packageName, out var packageId),
                "LsaLookupAuthenticationPackage");

            var request = new KerbQueryTicketCacheRequest
            {
                MessageType = KerbQueryTicketCacheExMessage,
                LogonId = default
            };

            var requestSize = Marshal.SizeOf<KerbQueryTicketCacheRequest>();
            requestBuffer = Marshal.AllocHGlobal(requestSize);
            Marshal.StructureToPtr(request, requestBuffer, false);

            var callStatus = LsaCallAuthenticationPackage(
                lsaHandle,
                packageId,
                requestBuffer,
                (uint)requestSize,
                out responseBuffer,
                out var responseLength,
                out var protocolStatus);

            ThrowForNtStatus(callStatus, "LsaCallAuthenticationPackage");
            ThrowForNtStatus(protocolStatus, "Kerberos authentication package");

            return ReadResponse(responseBuffer, responseLength, serviceFilter);
        }
        finally
        {
            if (responseBuffer != IntPtr.Zero)
            {
                _ = LsaFreeReturnBuffer(responseBuffer);
            }

            if (requestBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(requestBuffer);
            }

            if (packageBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(packageBuffer);
            }

            if (lsaHandle != IntPtr.Zero)
            {
                _ = LsaDeregisterLogonProcess(lsaHandle);
            }
        }
    }

    private static IReadOnlyList<ScrollRecord> ReadResponse(
        IntPtr responseBuffer,
        uint responseLength,
        string? serviceFilter)
    {
        var headerSize = Marshal.SizeOf<KerbQueryTicketCacheResponse>();
        if (responseBuffer == IntPtr.Zero || responseLength < headerSize)
        {
            throw new InvalidDataException("The Kerberos package returned an invalid response.");
        }

        var response = Marshal.PtrToStructure<KerbQueryTicketCacheResponse>(responseBuffer);
        if (response.CountOfTickets > MaximumTicketCount)
        {
            throw new InvalidDataException("The Kerberos package returned an unreasonable ticket count.");
        }

        var itemSize = Marshal.SizeOf<KerbTicketCacheInfoEx>();
        var requiredLength = checked((ulong)headerSize + ((ulong)response.CountOfTickets * (ulong)itemSize));
        if (requiredLength > responseLength)
        {
            throw new InvalidDataException("The Kerberos package returned a truncated ticket list.");
        }

        var scrolls = new List<ScrollRecord>((int)response.CountOfTickets);
        var ticketPointer = IntPtr.Add(responseBuffer, headerSize);

        for (var index = 0; index < response.CountOfTickets; index++)
        {
            var ticket = Marshal.PtrToStructure<KerbTicketCacheInfoEx>(ticketPointer);
            ticketPointer = IntPtr.Add(ticketPointer, itemSize);

            var serviceName = ReadUnicodeString(ticket.ServerName);
            var serviceRealm = ReadUnicodeString(ticket.ServerRealm);
            if (!MatchesFilter(serviceName, serviceRealm, serviceFilter))
            {
                continue;
            }

            scrolls.Add(new ScrollRecord(
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

    private static bool MatchesFilter(string serviceName, string serviceRealm, string? filter)
    {
        if (string.IsNullOrWhiteSpace(filter))
        {
            return true;
        }

        return serviceName.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
               serviceRealm.Contains(filter, StringComparison.OrdinalIgnoreCase);
    }

    private static string ReadUnicodeString(UnicodeString value)
    {
        if (value.Buffer == IntPtr.Zero || value.Length == 0)
        {
            return string.Empty;
        }

        if ((value.Length & 1) != 0 || value.Length > value.MaximumLength)
        {
            throw new InvalidDataException("The Kerberos package returned an invalid Unicode string.");
        }

        return Marshal.PtrToStringUni(value.Buffer, value.Length / 2) ?? string.Empty;
    }

    private static DateTimeOffset? ReadFileTime(long value)
    {
        if (value <= 0)
        {
            return null;
        }

        try
        {
            return new DateTimeOffset(DateTime.FromFileTimeUtc(value));
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static string NameEncryption(int encryptionType) => encryptionType switch
    {
        17 => "AES128-CTS-HMAC-SHA1-96",
        18 => "AES256-CTS-HMAC-SHA1-96",
        23 => "RC4-HMAC",
        24 => "RC4-HMAC-EXP",
        _ => $"etype-{encryptionType}"
    };

    private static void ThrowForNtStatus(int status, string operation)
    {
        if (status == 0)
        {
            return;
        }

        var error = checked((int)LsaNtStatusToWinError(status));
        throw new Win32Exception(error, $"{operation} failed.");
    }

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
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KerbQueryTicketCacheRequest
    {
        public int MessageType;
        public Luid LogonId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KerbQueryTicketCacheResponse
    {
        public int MessageType;
        public uint CountOfTickets;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KerbTicketCacheInfoEx
    {
        public UnicodeString ClientName;
        public UnicodeString ClientRealm;
        public UnicodeString ServerName;
        public UnicodeString ServerRealm;
        public long StartTime;
        public long EndTime;
        public long RenewTime;
        public int EncryptionType;
        public uint TicketFlags;
    }

    [DllImport("secur32.dll")]
    private static extern int LsaConnectUntrusted(out IntPtr lsaHandle);

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

    [DllImport("advapi32.dll")]
    private static extern uint LsaNtStatusToWinError(int status);
}
