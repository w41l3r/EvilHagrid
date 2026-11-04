# EvilHagrid

EvilHagrid is a deliberately narrow C# utility for auditing Kerberos cache metadata
in the current Windows logon session. Its small spell book keeps the playful naming
from the original Rust experiment while reducing the project to two read-only flows.

## Spells

```text
EvilHagrid census [--service <text>]
EvilHagrid pensieve --out <path.json> [--service <text>]
```

- `census` shows the client, service, validity times, encryption type, and ticket flags.
- `pensieve` writes the same metadata to a new JSON file and refuses to overwrite an
  existing file.

## Deliberate boundaries

- Windows only.
- Current logon session only, through an untrusted LSA connection.
- No raw ticket, `.kirbi`, session-key, or credential export.
- No cross-session enumeration, elevation, injection, network traffic, or persistence.
- No obfuscation or removal of license/provenance material.

The command shape is conceptually inspired by the defensive inspection use case of
GhostPack Rubeus `triage`. This branch is an independent implementation and contains
no copied Rubeus source. The raw-ticket behavior of Rubeus `dump` is intentionally not
implemented; `pensieve` is a metadata-only export.

## Build

The current validation environment provides .NET SDK 6.0.400:

```bash
dotnet build src/EvilHagrid/EvilHagrid.csproj --configuration Release
dotnet run --project src/EvilHagrid/EvilHagrid.csproj -- help
```

.NET 6 is end-of-life. Move the target framework to a supported LTS before production
deployment once the corresponding SDK is available in the build environment.

## Branches

- `main`: this C# metadata-audit rewrite.
- `unstable`: archived Rust implementation at its last pre-rewrite commit.

Use only on systems where you have explicit authorization to inspect the current
user's authentication metadata.
