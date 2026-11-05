using EvilHagrid.Domain;

namespace EvilHagrid.Spells;

internal static class DumpCharm
{
    private const int LineWidth = 100;

    public static int Cast(IReadOnlyList<KirbiRecord> kirbis)
    {
        if (kirbis.Count == 0)
        {
            Console.WriteLine("[*] No matching tickets found for the specified LUID.");
            return 0;
        }

        foreach (var kirbi in kirbis)
        {
            Console.WriteLine();
            Console.WriteLine($"  [*] LUID          : {TriageCharm.FormatLuid(kirbi.LuidLow, kirbi.LuidHigh)}");
            Console.WriteLine($"      UserName      : {Principal(kirbi.ClientName, kirbi.ClientRealm)}");
            Console.WriteLine($"      ServiceName   : {Principal(kirbi.ServiceName, kirbi.ServiceRealm)}");
            Console.WriteLine($"      StartTime     : {Time(kirbi.StartTimeUtc)}");
            Console.WriteLine($"      EndTime       : {Time(kirbi.EndTimeUtc)}");
            Console.WriteLine($"      Flags         : {kirbi.TicketFlags}");
            Console.WriteLine();
            Console.WriteLine("    Base64EncodedTicket :");
            Console.WriteLine();

            var b64 = kirbi.Base64Kirbi;
            for (var offset = 0; offset < b64.Length; offset += LineWidth)
            {
                Console.WriteLine($"      {b64[offset..Math.Min(offset + LineWidth, b64.Length)]}");
            }
        }

        Console.WriteLine();
        Console.WriteLine($"[*] Dumped {kirbis.Count} ticket(s).");
        return 0;
    }

    private static string Principal(string name, string realm) =>
        string.IsNullOrEmpty(realm) ? name : $"{name}@{realm}";

    private static string Time(DateTimeOffset? value) =>
        value?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss'Z'") ?? "n/a";
}
