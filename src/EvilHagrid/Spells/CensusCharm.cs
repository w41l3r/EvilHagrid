using EvilHagrid.Domain;
using EvilHagrid.Rendering;

namespace EvilHagrid.Spells;

internal static class CensusCharm
{
    public static int Cast(IReadOnlyList<ScrollRecord> scrolls)
    {
        if (scrolls.Count == 0)
        {
            Console.WriteLine("No matching Kerberos ticket metadata found in the current logon session.");
            return 0;
        }

        var rows = scrolls
            .Select(scroll => (IReadOnlyList<string>)new[]
            {
                Principal(scroll.ClientName, scroll.ClientRealm),
                Principal(scroll.ServiceName, scroll.ServiceRealm),
                Time(scroll.EndTimeUtc),
                scroll.EncryptionName,
                scroll.TicketFlags
            })
            .ToArray();

        GreatHallTable.Write(
            new[] { "Client", "Service", "Expires (UTC)", "Encryption", "Flags" },
            rows);
        Console.WriteLine();
        Console.WriteLine($"{scrolls.Count} metadata record(s); no ticket bytes or keys were read.");
        return 0;
    }

    private static string Principal(string name, string realm) =>
        string.IsNullOrEmpty(realm) ? name : $"{name}@{realm}";

    private static string Time(DateTimeOffset? value) =>
        value?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss'Z'") ?? "n/a";
}
