namespace EvilHagrid.Cli;

internal enum SpellName
{
    Help,
    Triage,
    Dump
}

internal sealed record Incantation(
    SpellName Spell,
    string? ServiceFilter = null,
    string? LuidHex = null);

internal sealed class IncantationException : Exception
{
    public IncantationException(string message) : base(message)
    {
    }
}

internal static class IncantationParser
{
    public static Incantation Parse(IReadOnlyList<string> arguments)
    {
        if (arguments.Count == 0 || IsHelp(arguments[0]))
        {
            return new Incantation(SpellName.Help);
        }

        var spell = arguments[0].ToLowerInvariant() switch
        {
            "triage" => SpellName.Triage,
            "dump"   => SpellName.Dump,
            _        => throw new IncantationException($"Unknown spell '{arguments[0]}'.")
        };

        string? serviceFilter = null;
        string? luidHex = null;

        for (var index = 1; index < arguments.Count; index++)
        {
            switch (arguments[index].ToLowerInvariant())
            {
                case "--service":
                    serviceFilter = ReadSingleValue(arguments, ref index, serviceFilter, "--service");
                    break;
                case "--luid":
                    luidHex = ReadSingleValue(arguments, ref index, luidHex, "--luid");
                    break;
                case "--help":
                case "-h":
                    return new Incantation(SpellName.Help);
                default:
                    throw new IncantationException($"Unknown option '{arguments[index]}'.");
            }
        }

        if (spell == SpellName.Dump && luidHex is null)
        {
            throw new IncantationException("The dump spell requires --luid <0x...>.");
        }

        if (spell == SpellName.Triage && luidHex is not null)
        {
            throw new IncantationException("The triage spell does not accept --luid.");
        }

        return new Incantation(spell, serviceFilter, luidHex);
    }

    private static string ReadSingleValue(
        IReadOnlyList<string> arguments,
        ref int index,
        string? existingValue,
        string option)
    {
        if (existingValue is not null)
        {
            throw new IncantationException($"Option '{option}' may only be supplied once.");
        }

        index++;
        if (index >= arguments.Count || string.IsNullOrWhiteSpace(arguments[index]))
        {
            throw new IncantationException($"Option '{option}' requires a value.");
        }

        return arguments[index];
    }

    private static bool IsHelp(string argument) =>
        argument.Equals("help", StringComparison.OrdinalIgnoreCase) ||
        argument.Equals("--help", StringComparison.OrdinalIgnoreCase) ||
        argument.Equals("-h", StringComparison.OrdinalIgnoreCase);
}
