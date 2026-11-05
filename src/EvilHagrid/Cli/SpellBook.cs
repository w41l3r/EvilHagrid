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

            if (incantation.Spell == SpellName.Triage)
            {
                var scrolls = ledger.ReadAllSessions(incantation.ServiceFilter);
                return TriageCharm.Cast(scrolls);
            }

            if (incantation.Spell == SpellName.Dump)
            {
                ParseLuid(incantation.LuidHex!, out var luidLow, out var luidHigh);
                var kirbis = ledger.RetrieveEncodedTickets(luidLow, luidHigh, incantation.ServiceFilter);
                return DumpCharm.Cast(kirbis);
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
        Console.WriteLine("  EvilHagrid triage [--service <text>]");
        Console.WriteLine("  EvilHagrid dump --luid <0x...> [--service <text>]");
        Console.WriteLine();
        Console.WriteLine("Spells:");
        Console.WriteLine("  triage    Enumerate Kerberos tickets across logon sessions (shows LUIDs).");
        Console.WriteLine("  dump      Dump the encoded ticket (base64 kirbi) for a specific LUID.");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  --luid <0x...>    Hexadecimal LUID from triage output (dump only).");
        Console.WriteLine("  --service <text>  Filter tickets whose service name or realm matches text.");
    }
}
