# Runbook cronológico de migração e validação

## Escopo e contexto

- Repositório: `/opt/tools/EvilHagrid`
- Data: `2026-11-04`
- Fuso horário: `America/Sao_Paulo` (`UTC-03:00`)
- Objetivo autorizado: preservar a implementação Rust em `unstable`, iniciar uma
  implementação C# mínima em `main` e validar localmente a nova árvore.
- Host de validação: Linux, .NET SDK `6.0.400`, Git `2.53.0`.
- Segredos: valores integrais existem somente em `.restricted/credentials.md`, modo
  `0600`, ignorado pelo Git. Este relatório usa identificadores estáveis.

## 1. Inspeção inicial do repositório

**Status:** `EXECUTADO`

**Objetivo:** confirmar branch, estado da árvore, remotos, histórico e instruções locais
antes de qualquer alteração.

**Diretório:** `/opt/tools/EvilHagrid`

**Comandos:**

```bash
git status --short --branch
git branch --all --verbose --no-abbrev
git remote -v
rg --files -g 'AGENTS.md'
git log -5 --oneline --decorate
```

**Saída capturada e sanitizada:**

```text
## master...origin/master

* master                0092a2ff07ac5768f964e584216e8dabd6d33cf4 fix: correct 8 protocol/safety bugs found by code review
  remotes/origin/master 0092a2ff07ac5768f964e584216e8dabd6d33cf4 fix: correct 8 protocol/safety bugs found by code review

origin  https://<CRED-GITHUB-001>@github.com/w41l3r/EvilHagrid.git (fetch)
origin  https://<CRED-GITHUB-001>@github.com/w41l3r/EvilHagrid.git (push)

rg exit code: 1; no local AGENTS.md found

0092a2f (HEAD -> master, origin/master) fix: correct 8 protocol/safety bugs found by code review
fe33d6a feat: implement all remaining Rubeus-equivalent spells
dd16736 fix: correct 8 protocol-correctness bugs found by code review
7c7f94a Update README.md
f4781a6 docs(readme): add Rubeus command mapping table
```

**Observações diretas:** a árvore rastreada estava limpa; `master` e
`origin/master` apontavam para `0092a2ff07ac5768f964e584216e8dabd6d33cf4`; a URL
do remoto continha um token em texto claro.

**Interpretação:** `CONFIRMADO` que havia material de credencial na configuração Git
local. A validade e o escopo do token não foram testados.

**Cautelas e limitações:** a consulta de remotos imprimiu o segredo no output bruto da
ferramenta durante a descoberta. O valor não é repetido neste relatório. Nenhuma
conexão ao GitHub foi feita nesta etapa.

## 2. Contenção do token no remoto local

**Status:** `EXECUTADO`

**Objetivo:** preservar o valor em inventário restrito, impedir versionamento acidental
e remover a credencial da URL do remoto sem validá-la.

**Timestamp capturado:** `2026-11-04T14:40:51-03:00`

**Comandos relevantes, com estrutura preservada:**

```bash
mkdir -p .restricted
# apply_patch criou .restricted/credentials.md com o identificador CRED-GITHUB-001
remote_url=$(git config --get remote.origin.url)
token_value=${remote_url#https://}
token_value=${token_value%@github.com/*}
sed -i "s|__FULL_SECRET_FROM_GIT_REMOTE__|${token_value}|" .restricted/credentials.md
chmod 600 .restricted/credentials.md
git remote set-url origin https://github.com/w41l3r/EvilHagrid.git
stat -c '%a %n' .restricted/credentials.md
git config --get remote.origin.url
```

**Saída capturada:**

```text
Primeira tentativa de git remote set-url:
error: could not lock config file .git/config: Read-only file system
fatal: could not set 'remote.origin.url' to 'https://github.com/w41l3r/EvilHagrid.git'
exit code: 128

Reexecução autorizada fora da restrição de escrita:
<sem stdout/stderr>
exit code: 0

600 .restricted/credentials.md
https://github.com/w41l3r/EvilHagrid.git
```

**Interpretação:** `CONFIRMADO` que o inventário restrito foi populado e recebeu modo
`0600`; `CONFIRMADO` que a URL local não contém mais o token.

**Limitação:** revogação ou rotação no GitHub não foi executada. O token permanece
`NOT TESTED` e deve ser tratado como comprometido.

## 3. Arquivamento local do projeto Rust

**Status:** `EXECUTADO`

**Objetivo:** preservar o commit original em `unstable` e criar uma história raiz nova
para o projeto C#.

**Comandos:**

```bash
git branch unstable master
git switch --orphan main
git show-ref --heads
```

**Saída capturada:**

```text
git branch unstable master
<sem stdout/stderr>
exit code: 0

Switched to a new branch 'main'
exit code: 0

0092a2ff07ac5768f964e584216e8dabd6d33cf4 refs/heads/master
0092a2ff07ac5768f964e584216e8dabd6d33cf4 refs/heads/unstable
```

**Interpretação:** `CONFIRMADO` que `unstable` preserva exatamente o último commit do
projeto Rust. `main` foi criada localmente como branch órfã.

**Limitações:** build artifacts Rust preexistentes (`target/` e `Cargo.lock`) continuam
no disco local, agora ignorados; não são parte da nova árvore. Nenhuma branch remota foi
criada ou alterada.

## 4. Implementação C# mínima

**Status:** `EXECUTADO`

**Objetivo:** criar uma ferramenta sem dependências externas com apenas dois fluxos:
`census` e `pensieve`.

**Método:** arquivos criados por `apply_patch`; o conteúdo integral e reproduzível é a
árvore rastreada da branch `main`. Arquivos materiais:

```text
src/EvilHagrid/Cli/Incantation.cs
src/EvilHagrid/Cli/SpellBook.cs
src/EvilHagrid/Domain/ScrollRecord.cs
src/EvilHagrid/Ministry/MinistryLedger.cs
src/EvilHagrid/Rendering/GreatHallTable.cs
src/EvilHagrid/Spells/CensusCharm.cs
src/EvilHagrid/Spells/PensieveCharm.cs
src/EvilHagrid/EvilHagrid.csproj
src/EvilHagrid/Program.cs
```

**Observações diretas:**

- `census` solicita apenas `KerbQueryTicketCacheExMessage` com LUID zero por uma conexão
  LSA não confiável, limitando a consulta à sessão corrente.
- `pensieve` serializa os mesmos metadados e usa `FileMode.CreateNew`, sem sobrescrita.
- Não há código de recuperação de ticket codificado, `.kirbi`, chave de sessão,
  enumeração de sessões, elevação, injeção, rede ou persistência.
- A implementação é independente; nenhum fonte do Rubeus foi copiado.

**Interpretação:** as restrições de capacidade estão `CONFIRMADAS` por inspeção estática
da árvore atual. O comportamento do ABI Windows continua `NÃO VERIFICADO` em runtime.

## 5. Build Release

**Status:** `EXECUTADO`

**Objetivo:** confirmar restauração local, compilação e ausência de warnings.

**Pré-requisito:** .NET SDK `6.0.400` já instalado. O projeto não possui pacotes NuGet
externos.

**Comando:**

```bash
dotnet build src/EvilHagrid/EvilHagrid.csproj --configuration Release --nologo
```

**Saída capturada:**

```text
Determining projects to restore...
Restored /opt/tools/EvilHagrid/src/EvilHagrid/EvilHagrid.csproj (in 64 ms).
EvilHagrid -> /opt/tools/EvilHagrid/src/EvilHagrid/bin/Release/net6.0/EvilHagrid.dll

Build succeeded.
    0 Warning(s)
    0 Error(s)

Time Elapsed 00:00:02.98
exit code: 0
```

**Interpretação:** build local `CONFIRMADO`.

**Limitação:** .NET 6 está fora de suporte; a escolha reproduz o SDK disponível neste
host, não uma recomendação de produção.

## 6. Formatação e análise estática do SDK

**Status:** `EXECUTADO`

**Objetivo:** validar estilo e analyzers sem alterar arquivos.

**Comando:**

```bash
dotnet format src/EvilHagrid/EvilHagrid.csproj --verify-no-changes --no-restore --verbosity diagnostic
```

**Saída relevante capturada:**

```text
The dotnet runtime version is '6.0.8'.
The dotnet CLI version is '6.0.400'.
Running 134 analyzers on EvilHagrid.
Formatted 0 of 11 files.
Format complete in 3325ms.
exit code: 0
```

**Interpretação:** conformidade de formatação `CONFIRMADA`; nenhum arquivo foi reescrito.

## 7. Testes de CLI e falha fechada fora do Windows

**Status:** `EXECUTADO`

**Objetivo:** exercitar ajuda, erros de parsing e a barreira de plataforma sem tráfego
de rede ou acesso a credenciais.

**Comandos:**

```bash
dotnet src/EvilHagrid/bin/Release/net6.0/EvilHagrid.dll help
dotnet src/EvilHagrid/bin/Release/net6.0/EvilHagrid.dll avada-kedavra
dotnet src/EvilHagrid/bin/Release/net6.0/EvilHagrid.dll pensieve
dotnet src/EvilHagrid/bin/Release/net6.0/EvilHagrid.dll census --service krbtgt
dotnet src/EvilHagrid/bin/Release/net6.0/EvilHagrid.dll pensieve --out /tmp/evilhagrid-pensieve-platform-test-20261104T144051.json
test ! -e /tmp/evilhagrid-pensieve-platform-test-20261104T144051.json
```

**Saída capturada:**

```text
help: exit 0
EvilHagrid — a narrow Kerberos cache metadata auditor
[uso e duas spells exibidos]

avada-kedavra: exit 2
[!] Unknown spell 'avada-kedavra'.
    Try: EvilHagrid help

pensieve sem --out: exit 2
[!] The pensieve spell requires --out <path>.
    Try: EvilHagrid help

census no Linux: exit 3
[!] Kerberos cache inspection is available on Windows only; no action was performed.

pensieve no Linux: exit 3
[!] Kerberos cache inspection is available on Windows only; no action was performed.

test de ausência do JSON: exit 0, sem saída
```

**Interpretação:** parsing e falha fechada fora do Windows estão `CONFIRMADOS`; não foi
criado arquivo de saída no teste negativo.

## 8. Varreduras de segredo e capacidade

**Status:** `EXECUTADO`

**Objetivo:** detectar credenciais acidentais e primitivas fora do escopo.

**Comandos:**

```bash
rg -n --hidden -g '!.git/**' -g '!.restricted/**' -g '!target/**' -g '!Cargo.lock' \
  'ghp_|github_pat_|AKIA|BEGIN (RSA|OPENSSH|EC) PRIVATE KEY|password\s*[:=]|token\s*[:=]'
rg -n 'KerbRetrieveEncodedTicket|RetrieveTicket|session.?key|\.kirbi|LsaEnumerateLogonSessions|HttpClient|WebClient|Socket|Process\.Start|CreateProcess|VirtualAlloc|WriteProcessMemory' \
  src README.md SECURITY.md
```

**Saída capturada:**

```text
Varredura de segredos: exit 1, sem correspondências.

README.md:22:- No raw ticket, `.kirbi`, session-key, or credential export.
SECURITY.md:4:session. It does not retrieve encoded tickets, session keys, or credentials.
```

**Interpretação:** `CONFIRMADO` que os padrões apareceram somente em negações
documentais; nenhuma primitiva correspondente apareceu em `src/`.

**Limitação:** buscas por padrão não substituem revisão completa nem execução em Windows.

## 9. Validação funcional em Windows

**Status:** `AVALIADO — NÃO EXECUTADO`

**Objetivo proposto:** confirmar marshalling/ABI e saída contra o cache da sessão do
usuário de teste em um host Windows autorizado.

**Comandos propostos:**

```powershell
dotnet build .\src\EvilHagrid\EvilHagrid.csproj --configuration Release
dotnet .\src\EvilHagrid\bin\Release\net6.0\EvilHagrid.dll census
dotnet .\src\EvilHagrid\bin\Release\net6.0\EvilHagrid.dll pensieve --out .\pensieve.json
```

**Output capturado:** nenhum; comandos não executados.

**Telemetria e cautela:** chamadas locais a `LsaConnectUntrusted`,
`LsaLookupAuthenticationPackage` e `LsaCallAuthenticationPackage` podem aparecer em
telemetria EDR/ETW. O JSON conterá nomes de contas, realms e serviços e deve ser tratado
como sensível. Não há tráfego de rede intencional.

**Conclusão:** compatibilidade runtime Windows `NÃO VERIFICADA`.

## 10. Publicação no GitHub

**Status:** `AVALIADO — NÃO EXECUTADO`

**Objetivo proposto:** publicar `unstable` e `main` e tornar `main` a branch padrão.

**Comandos candidatos:**

```bash
git push origin unstable:unstable
git push --set-upstream origin main:main
gh repo edit w41l3r/EvilHagrid --default-branch main
```

**Output capturado:** nenhum; não houve conexão nem alteração remota.

**Telemetria e risco operacional:** os pushes criarão refs e podem disparar webhooks ou
workflows; a troca da branch padrão ficará nos audit logs do GitHub e altera a landing
page/clones futuros. A remoção de `origin/master` não está incluída; fazê-la seria uma
ação destrutiva separada, recuperável por `unstable`, mas requer autorização específica.

## 11. Commit raiz e verificação das referências locais

**Status:** `EXECUTADO`

**Objetivo:** materializar a nova árvore em uma referência Git reproduzível e confirmar
que o inventário restrito permaneceu fora do commit.

**Comandos:**

```bash
git commit -m "feat: restart EvilHagrid as narrow C# metadata auditor"
git status --short --branch --untracked-files=all
git rev-parse main unstable master
git ls-tree -r --name-only main
git grep -n -E 'ghp_|github_pat_|AKIA|BEGIN (RSA|OPENSSH|EC) PRIVATE KEY' \
  main -- . ':!docs/validation-runbook.md'
```

**Saída capturada:**

```text
[main (root-commit) 821b76a] feat: restart EvilHagrid as narrow C# metadata auditor
16 files changed, 1107 insertions(+)

## main

821b76acc27458650cd18aa17ad00372a183a596
0092a2ff07ac5768f964e584216e8dabd6d33cf4
0092a2ff07ac5768f964e584216e8dabd6d33cf4

git grep: exit 1, sem correspondências
```

**Interpretação:** `CONFIRMADO` que `main` possui história raiz independente, que
`unstable` e `master` preservam o commit Rust e que nenhum padrão de segredo conhecido
foi encontrado na árvore commitada. `.restricted/credentials.md` não aparece no tree.

## Conclusões materiais

1. `CONFIRMADO`: o projeto Rust está preservado localmente em `unstable` no commit
   `0092a2ff07ac5768f964e584216e8dabd6d33cf4`.
2. `CONFIRMADO`: a nova árvore C# compila com zero warnings/erros e possui apenas os
   fluxos de metadados `census` e `pensieve`.
3. `CONFIRMADO`: o token `CRED-GITHUB-001` foi removido da URL local e isolado em
   inventário `0600`; revogação remota ainda é necessária.
4. `NÃO VERIFICADO`: execução real do caminho LSA em Windows.
5. `NÃO VERIFICADO`: estado remoto das novas branches e branch padrão, pois publicação
   ainda não foi executada.
