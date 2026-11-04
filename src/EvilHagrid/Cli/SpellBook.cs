using EvilHagrid.Ministry;
using EvilHagrid.Spells;

namespace EvilHagrid.Cli;

internal static class SpellBook
{
    public static async Task<int> CastAsync(string[] arguments)
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
            var scrolls = ledger.ReadCurrentSession(incantation.ServiceFilter);

            return incantation.Spell switch
            {
                SpellName.Census => CensusCharm.Cast(scrolls),
                SpellName.Pensieve => await PensieveCharm.CastAsync(scrolls, incantation.OutputPath!),
                _ => 1
            };
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

    private static void PrintHelp()
    {
        Console.WriteLine("EvilHagrid — a narrow Kerberos cache metadata auditor");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  EvilHagrid census [--service <text>]");
        Console.WriteLine("  EvilHagrid pensieve --out <path.json> [--service <text>]");
        Console.WriteLine();
        Console.WriteLine("Spells:");
        Console.WriteLine("  census    Show ticket metadata from the current Windows logon session.");
        Console.WriteLine("  pensieve  Save the same metadata as JSON without ticket bytes or keys.");
    }
}
