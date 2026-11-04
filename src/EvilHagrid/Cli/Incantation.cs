namespace EvilHagrid.Cli;

internal enum SpellName
{
    Help,
    Census,
    Pensieve
}

internal sealed record Incantation(
    SpellName Spell,
    string? ServiceFilter = null,
    string? OutputPath = null);

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
            "census" => SpellName.Census,
            "pensieve" => SpellName.Pensieve,
            _ => throw new IncantationException($"Unknown spell '{arguments[0]}'.")
        };

        string? serviceFilter = null;
        string? outputPath = null;

        for (var index = 1; index < arguments.Count; index++)
        {
            switch (arguments[index].ToLowerInvariant())
            {
                case "--service":
                    serviceFilter = ReadSingleValue(arguments, ref index, serviceFilter, "--service");
                    break;
                case "--out":
                    outputPath = ReadSingleValue(arguments, ref index, outputPath, "--out");
                    break;
                case "--help":
                case "-h":
                    return new Incantation(SpellName.Help);
                default:
                    throw new IncantationException($"Unknown option '{arguments[index]}'.");
            }
        }

        if (spell == SpellName.Census && outputPath is not null)
        {
            throw new IncantationException("The census spell does not accept --out.");
        }

        if (spell == SpellName.Pensieve && outputPath is null)
        {
            throw new IncantationException("The pensieve spell requires --out <path>.");
        }

        return new Incantation(spell, serviceFilter, outputPath);
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
