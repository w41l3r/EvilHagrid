using EvilHagrid.Ministry;
using EvilHagrid.Spells;

namespace EvilHagrid.Cli;

internal static class SpellBook
{
    public static int Cast(string[] arguments)
    {
        try
        {
            var incantation = IncantationParser.Parse(arguments);
            if (incantation.Spell == SpellName.Help)
            {
                PrintHelp();
                return 0;
            }

            var ledger = new MinistryLedger();

            if (incantation.Spell == SpellName.Accio)
            {
                var scrolls = ledger.ReadAllSessions(incantation.ServiceFilter);
                return TriageCharm.Cast(scrolls);
            }

            if (incantation.Spell == SpellName.Aparecium)
            {
                ParseLuid(incantation.LuidHex!, out var luidLow, out var luidHigh);
                var kirbis = ledger.RetrieveEncodedTickets(luidLow, luidHigh, incantation.ServiceFilter);
                return DumpCharm.Cast(kirbis, incantation.NoWrap);
            }

            return 1;
        }
        catch (IncantationException exception)
        {
            Console.Error.WriteLine($"[!] {exception.Message}");
            Console.Error.WriteLine("    Try: EvilHagrid help");
            return 2;
        }
        catch (PlatformNotSupportedException exception)
        {
            Console.Error.WriteLine($"[!] {exception.Message}");
            return 3;
        }
        catch (UnauthorizedAccessException exception)
        {
            Console.Error.WriteLine($"[!] Access denied: {exception.Message}");
            return 4;
        }
        catch (IOException exception)
        {
            Console.Error.WriteLine($"[!] I/O failure: {exception.Message}");
            return 5;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"[!] {exception.Message}");
            return 1;
        }
    }

    private static void ParseLuid(string luidHex, out uint luidLow, out int luidHigh)
    {
        var hex = luidHex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? luidHex[2..]
            : luidHex;

        if (!ulong.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out var value))
        {
            throw new IncantationException(
                $"Invalid LUID '{luidHex}'. Expected hexadecimal (e.g. 0x3e7).");
        }

        luidLow  = (uint)(value & 0xFFFFFFFF);
        luidHigh = (int)(value >> 32);
    }

    private static void PrintHelp()
    {
        Console.WriteLine("EvilHagrid — Kerberos ticket utility");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  EvilHagrid accio [--service <text>]");
        Console.WriteLine("  EvilHagrid aparecium --luid <0x...> [--service <text>]");
        Console.WriteLine();
        Console.WriteLine("Spells:");
        Console.WriteLine("  accio       Enumerate Kerberos tickets across logon sessions (shows LUIDs).");
        Console.WriteLine("  aparecium   Dump the encoded ticket (base64 kirbi) for a specific LUID.");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  --luid <0x...>    Hexadecimal LUID from accio output (aparecium only).");
        Console.WriteLine("  --service <text>  Filter tickets whose service name or realm matches text.");
        Console.WriteLine("  --nowrap          Print base64 ticket as a single line (aparecium only).");
    }
}
