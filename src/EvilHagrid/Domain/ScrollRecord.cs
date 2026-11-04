namespace EvilHagrid.Domain;

internal sealed record ScrollRecord(
    string ClientName,
    string ClientRealm,
    string ServiceName,
    string ServiceRealm,
    DateTimeOffset? StartTimeUtc,
    DateTimeOffset? EndTimeUtc,
    DateTimeOffset? RenewTimeUtc,
    int EncryptionType,
    string EncryptionName,
    string TicketFlags);
