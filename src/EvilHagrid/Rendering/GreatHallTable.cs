namespace EvilHagrid.Rendering;

internal static class GreatHallTable
{
    private const int MaximumColumnWidth = 48;

    public static void Write(IReadOnlyList<string> headings, IReadOnlyList<IReadOnlyList<string>> rows)
    {
        var safeHeadings = headings.Select(Clean).ToArray();
        var safeRows = rows.Select(row => row.Select(Clean).ToArray()).ToArray();
        var widths = new int[safeHeadings.Length];

        for (var column = 0; column < widths.Length; column++)
        {
            widths[column] = safeHeadings[column].Length;
            foreach (var row in safeRows)
            {
                widths[column] = Math.Min(MaximumColumnWidth, Math.Max(widths[column], row[column].Length));
            }
        }

        PrintRow(safeHeadings, widths);
        Console.WriteLine(string.Join("-+-", widths.Select(width => new string('-', width))));
        foreach (var row in safeRows)
        {
            PrintRow(row, widths);
        }
    }

    private static void PrintRow(IReadOnlyList<string> values, IReadOnlyList<int> widths)
    {
        var cells = values.Select((value, index) => Clip(value, widths[index]).PadRight(widths[index]));
        Console.WriteLine(string.Join(" | ", cells));
    }

    private static string Clean(string value) =>
        value.Replace('\r', ' ').Replace('\n', ' ').Replace('\t', ' ');

    private static string Clip(string value, int width) =>
        value.Length <= width ? value : $"{value[..(width - 1)]}…";
}
