namespace EvilHagrid.Domain;

internal sealed record KirbiRecord(
    uint LuidLow,
    int LuidHigh,
    string ClientName,
    string ClientRealm,
    string ServiceName,
    string ServiceRealm,
    DateTimeOffset? StartTimeUtc,
    DateTimeOffset? EndTimeUtc,
    string TicketFlags,
    string Base64Kirbi);
