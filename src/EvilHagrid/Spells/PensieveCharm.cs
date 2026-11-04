using System.Text.Json;
using EvilHagrid.Domain;

namespace EvilHagrid.Spells;

internal static class PensieveCharm
{
    public static async Task<int> CastAsync(IReadOnlyList<ScrollRecord> scrolls, string outputPath)
    {
        var fullPath = Path.GetFullPath(outputPath);
        var directory = Path.GetDirectoryName(fullPath);
        if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException($"Output directory does not exist: {directory}");
        }

        var report = new PensieveReport(
            1,
            DateTimeOffset.UtcNow,
            "Current Windows logon session; metadata only",
            scrolls.Count,
            scrolls);

        await using var stream = new FileStream(
            fullPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            16_384,
            FileOptions.Asynchronous | FileOptions.WriteThrough);

        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = true
        };

        await JsonSerializer.SerializeAsync(stream, report, options);
        await stream.FlushAsync();
        Console.WriteLine($"Pensieve wrote {scrolls.Count} metadata record(s) to {fullPath}.");
        return 0;
    }

    private sealed record PensieveReport(
        int SchemaVersion,
        DateTimeOffset GeneratedAtUtc,
        string Scope,
        int Count,
        IReadOnlyList<ScrollRecord> Tickets);
}
