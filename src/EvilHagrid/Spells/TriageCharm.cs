using EvilHagrid.Domain;
using EvilHagrid.Rendering;

namespace EvilHagrid.Spells;

internal static class TriageCharm
{
    public static int Cast(IReadOnlyList<ScrollRecord> scrolls)
    {
        if (scrolls.Count == 0)
        {
            Console.WriteLine("No matching Kerberos tickets found in the enumerated logon sessions.");
            return 0;
        }

        var rows = scrolls
            .Select(s => (IReadOnlyList<string>)new[]
            {
                FormatLuid(s.LuidLow, s.LuidHigh),
                Principal(s.ClientName, s.ClientRealm),
                Principal(s.ServiceName, s.ServiceRealm),
                Time(s.EndTimeUtc),
                s.EncryptionName,
                s.TicketFlags
            })
            .ToArray();

        GreatHallTable.Write(
            new[] { "LUID", "Client", "Service", "Expires (UTC)", "Encryption", "Flags" },
            rows);
        Console.WriteLine();
        Console.WriteLine($"{scrolls.Count} ticket(s) enumerated.");
        return 0;
    }

    internal static string FormatLuid(uint low, int high)
    {
        if (high == 0)
            return $"0x{low:x}";

        var full = ((ulong)(uint)high << 32) | low;
        return $"0x{full:x}";
    }

    private static string Principal(string name, string realm) =>
        string.IsNullOrEmpty(realm) ? name : $"{name}@{realm}";

    private static string Time(DateTimeOffset? value) =>
        value?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss'Z'") ?? "n/a";
}
