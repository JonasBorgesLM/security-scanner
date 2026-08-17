# security-scanner

Ferramenta de estudo em Go para descobrir vulnerabilidades numa API, confirmá-las
via ataques controlados e gerar um relatório final.

---

## ⚠️ Escopo de uso

**Use esta ferramenta exclusivamente contra infraestrutura que você mesmo opera ou
está formalmente autorizado a testar.**

Escanear sistemas de terceiros sem autorização por escrito é ilegal na maior parte
das jurisdições. Este projeto foi construído para uma API de laboratório do próprio
autor, num ambiente controlado, e nada aqui muda essa responsabilidade: quem executa
a ferramenta responde pelo alvo que escolheu.

A ferramenta impõe essa restrição tecnicamente, não só por convenção:

- **`scope.allowed_hosts`** no `config.yaml` é uma allowlist obrigatória. Todo request
  passa pelo `ScopeGuard` dentro do único cliente HTTP do projeto; um host fora da
  lista é rejeitado **antes de a conexão ser aberta** — inclusive a cada salto de um
  redirecionamento HTTP, não só na requisição inicial (um alvo malicioso ou mal
  configurado não consegue usar um `3xx` pra desviar o scanner pra outro host).
- O scanner **se recusa a iniciar** se o host do `target.base_url` não estiver na
  allowlist — configuração incoerente falha cedo, com mensagem explícita.
- **Não-destrutivo por padrão:** endpoints `DELETE`/`PUT`/`PATCH` são pulados a menos
  que `engine.test_destructive: true` seja definido explicitamente.
- **A coleta inicial só usa métodos seguros.** Um endpoint declarado como `POST` é
  sondado com `GET` — a fase que monta a baseline nunca cria nem destrói nada no alvo.
- **Gentil por design:** worker pool + rate limiter evitam derrubar o próprio alvo.

---

## Requisitos

- Go 1.25 ou superior (veja `go.mod`). O piso é ditado pelas dependências
  (`kin-openapi`, `golang.org/x/time`), não pelo código do scanner em si.

## Build

```bash
go build -o scanner ./cmd/scanner
```

## Configuração

Copie o exemplo comentado e ajuste para o seu laboratório:

```bash
cp configs/config.yaml meu-lab.yaml
```

Campos obrigatórios (a ferramenta valida todos e reporta **todos** os que faltarem
de uma vez, não um por execução):

| Campo | Descrição |
|---|---|
| `schema_version` | Precisa ser `1` |
| `target.base_url` | URL absoluta da API sob teste |
| `scope.allowed_hosts` | Allowlist de `host:porta`; precisa incluir o host do target |
| `engine.max_concurrency` | Tamanho do worker pool (> 0) |
| `engine.requests_per_second` | Limite de taxa (> 0) |
| `engine.timeout` | Deadline global da execução, ex. `5m` |
| `checks.enabled` | Lista de checks a executar |

O bloco **`auth` é opcional**: um alvo cujo spec não declara nenhuma rota
protegida pode ser escaneado sem seção `auth` alguma. Quando presente, ele é
**tudo-ou-nada** — se qualquer campo de auth aparecer, o conjunto completo é
exigido (`login_endpoint`, `token_path`, `credentials.username`,
`credentials.password`), porque um bloco pela metade quase sempre é um erro
(chave digitada errada, campo esquecido). Se o spec tiver rotas protegidas mas
o config não tiver bloco `auth`, o `scan`/`attack` falha com mensagem clara em
vez de escanear as rotas sem autenticação.

| Campo (auth, opcional) | Descrição |
|---|---|
| `auth.login_endpoint` | Rota de login, resolvida contra o `base_url` |
| `auth.credentials.username` / `password` | Credenciais do lab |
| `auth.token_path` | Caminho em notação de ponto até o token no JSON de resposta |

### Variáveis de ambiente

Segredos **nunca** vão no arquivo de configuração. Escreva-os como `${VAR}` e
exporte antes de rodar — a expansão acontece nos valores do YAML (comentários são
ignorados), e uma variável não definida aborta a execução com o nome dela na
mensagem, em vez de mandar o literal `${VAR}` como senha para o alvo.

| Variável | Usada em | Descrição |
|---|---|---|
| `LAB_PASSWORD` | `auth.credentials.password` no `configs/config.yaml` de exemplo | Senha do usuário de teste do laboratório |

```bash
export LAB_PASSWORD='sua-senha-de-lab'
```

Qualquer `${OUTRA_VAR}` que você adicionar ao seu config passa a ser obrigatória da
mesma forma.

---

## Uso

O pipeline é dividido em três subcomandos encadeados por arquivos JSON versionados.
Cada arquivo intermediário é o contrato entre estágios: versionável no git, revisável
à mão antes do `attack`, e reexecutável em outra máquina.

```bash
scanner scan   --spec openapi.yaml --config config.yaml --out findings.json
scanner attack --in findings.json  --config config.yaml --out confirmed.json
scanner report --in confirmed.json --out report.html [--json report.json]
```

- **`scan`** — importa as rotas do OpenAPI, autentica no alvo, roda os checks e grava
  `findings.json` (suspeitas, `confirmed: false`).
- **`attack`** — reproduz cada suspeita com uma prova de conceito não-destrutiva e
  grava `confirmed.json`.
- **`report`** — lê `confirmed.json` e grava `report.html` + `report.json`: resumo
  executivo por severidade no topo, e por achado o check, endpoint, categoria OWASP,
  severidade, evidência (request e response) e uma recomendação de correção.

### Estado atual

O projeto está em construção. Hoje:

| Estágio | Estado |
|---|---|
| `scan` | **Funcional.** Importa o spec, autentica, coleta uma baseline por endpoint, roda os checks habilitados e grava `findings.json`. |
| `attack` | **Funcional.** Lê `findings.json`, reproduz cada suspeita não confirmada com uma PoC não-destrutiva e grava `confirmed.json`. |
| `report` | **Funcional.** Lê `confirmed.json` e grava `report.html` (via `html/template`) + `report.json`. Não toca a rede. |

Checks implementados:

| Check | Tipo | O que reporta |
|---|---|---|
| `missing-headers` | passivo | Cabeçalhos de segurança ausentes na resposta: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`. Severidade média, OWASP A05. |
| `exposed-secrets` | passivo | Credenciais no corpo da resposta, inclusive dentro de comentários HTML/JS: chaves de nuvem, tokens de serviço, blocos de chave privada, JWTs e atribuições genéricas (`api_key`, `password`, `Bearer`, connection strings). OWASP A02. |
| `sqli-boolean` | ativo | SQLi boolean-based em parâmetros de query/path: injeta uma condição sempre-verdadeira e uma sempre-falsa e compara as respostas contra o ruído medido do próprio endpoint. OWASP A03, severidade alta. |

Os padrões de `exposed-secrets` ficam em `internal/checks/patterns/secrets.txt`,
embutidos via `go:embed` — dá para estender a lista sem tocar na lógica do check.
Cada padrão declara confiança `high` ou `low`: os genéricos (`low`) só viram
finding depois de passar por um filtro de placeholders, para que
`"password": "changeme"` num exemplo de documentação não vire ruído.

O `sqli-boolean` é o primeiro check **ativo**: em vez de ler a baseline coletada
uma vez pelo engine, ele envia seus próprios requests. Para cada parâmetro de
query/path do endpoint, mede o ruído de conteúdo dinâmico repetindo um request
benigno 3 vezes, injeta pares verdadeiro/falso de `internal/checks/payloads/sqli.txt`
(também via `go:embed`) e só marca suspeita se a diferença de tamanho entre as
duas respostas for **maior** que o ruído já observado — é a defesa contra
falso-positivo descrita no invariante #4. O `CapturedRequest` de cada finding
carrega a URL exata que produziu o resultado, pronta para o estágio `attack`
(ou um `curl` manual) reproduzir.

**Segredos são redigidos no relatório** (`AKIA****************`, com o tamanho).
Um scanner de secrets que escreve o segredo dentro de um `findings.json`
versionado mudou o vazamento de lugar em vez de encontrá-lo.

Um nome desconhecido em `checks.enabled` aborta a execução antes de qualquer
request — um typo não desabilita um check em silêncio.

O `report` usa `html/template` (não `text/template`) de propósito: `Evidence` e
`Request` carregam conteúdo potencialmente controlado por quem foi atacado —
payload de SQLi, marcador de XSS refletido, trecho cru de resposta — e isso
precisa sair como texto inerte na página, nunca como HTML executável. Achados
são ordenados por severidade e depois por confirmado-antes-de-não-confirmado,
não pela ordem em que o scan os encontrou, para que o leitor veja primeiro o
que mais importa. `report.json` carrega o mesmo resumo e a mesma ordem, então
os dois arquivos são a mesma informação em dois formatos, não dois relatórios
diferentes. O texto de recomendação por check vive só no pacote `report`
(não em `model.Finding`): é conteúdo de apresentação, não parte do contrato
JSON versionado das outras duas etapas.

### `attack`: prova de conceito não-destrutiva

`attack` é uma execução separada do binário — não compartilha nada com o `scan`
além dos arquivos, autentica de novo do zero — que lê cada `Finding` de
`findings.json` e tenta confirmá-lo com uma técnica específica do check que o
gerou, via um pequeno registry (`internal/attack`, mesmo padrão `init()` de
`internal/checks`):

| Check | Confirmação |
|---|---|
| `sqli-boolean` | Mede o ruído do endpoint de novo, agora, e só confirma se a diferença verdadeiro/falso ainda for maior que o ruído — o alvo pode ter mudado desde o `scan`. Confirmado isso, tenta extrair **só o nome do banco** via `UNION SELECT` (nunca escrita: sem `DROP`, sem `UPDATE`, só leitura), testando contagem de colunas e algumas funções comuns (`database()`, `current_database()`, `DB_NAME()`, `sqlite_version()`). A extração é *best-effort*: se não funcionar contra o motor do alvo, o finding continua confirmado pela reprodução booleana — só a nota de extração muda. |
| `xss-reflected` | Reenvia com um marcador **novo e único** (não o payload original do scan, para não aproveitar uma resposta em cache) e confirma só se ele voltar sem escape HTML — reflexão escapada não é explorável e é reportada como tal, não como "não reproduziu". |

Um `CheckName` sem confirmer registrado (`missing-headers`, `exposed-secrets` — são
observações diretas de uma única resposta já coletada, não têm o que "reproduzir")
passa por `confirmed.json` sem alteração, listado como `skipped`, nunca promovido
a `Confirmed: true` sem verificação real.

Endpoint `Destructive` é respeitado de novo aqui, independente do que o `scan` já
fez — `attack` é um processo separado e não assume que a decisão de outro processo
ainda vale.

Exemplo:

```console
$ scanner attack --in findings.json --config configs/config.yaml
target:     http://127.0.0.1:8099
findings:   17 (0 destructive)

wrote confirmed.json (1 confirmed, 16 skipped, 0 failed, 0 not confirmed)
  skipped: missing-headers on GET /health: no PoC available for check "missing-headers"
  ...
```

O finding de `sqli-boolean` confirmado carrega a URL exata que extraiu o dado —
reproduzível com `curl` puro, sem o scanner:

```console
$ curl 'http://127.0.0.1:8099/items?q=%27+UNION+SELECT+CONCAT%28%27ATTACKPOC_%27%2Cdatabase%28%29%2C%27_ENDPOC%27%29--+-'
{"items": [{"id": 1, "name": "ATTACKPOC_labdb_billing_ENDPOC"}]}
```

Exemplo de execução do `scan`:

```console
$ export LAB_PASSWORD='...'
$ scanner scan --spec openapi.yaml --config configs/config.yaml
target:     http://localhost:8080
scope:      [localhost:8080 127.0.0.1:8080]
spec:       openapi.yaml
endpoints:  6 (5 require auth, 2 destructive)
checks:     exposed-secrets, missing-headers, sqli-boolean
            2 destructive endpoint(s) will be skipped (engine.test_destructive is false)

wrote findings.json (17 findings, 0 skipped, 0 failed)
```

Endpoints que não puderam ser examinados aparecem como `skipped`, com o motivo —
nunca como "limpos".

Ordem de implementação dos checks: headers ausentes (passivo) → secrets expostos
(passivo) → SQLi boolean-based (ativo) → XSS refletido (ativo) → IDOR / JWT fraco
(fase 2). Ver `doc/security-scanner-projeto.md` §7.

---

## Lab

`lab/` é uma API em Go **propositalmente vulnerável**, atrás de um Postgres real,
só para dar ao scanner um alvo próprio pra rodar o ciclo completo contra —
nada aqui deve rodar em outro lugar além da sua máquina. É um módulo Go
separado (`lab/go.mod`); `go build ./...` na raiz do repo não o toca.

| Vulnerabilidade | Onde | Como |
|---|---|---|
| SQLi boolean-based | `GET /items?q=` | `q` é concatenado sem sanitização num `WHERE name = '<q>'`. Detectado por `sqli-boolean`; `attack` reproduz e ainda extrai o nome do banco via `UNION SELECT` de verdade contra o Postgres. |
| Secrets expostos | `GET /debug` | Uma chave no formato AWS (o exemplo público da própria AWS, não é credencial real) e um `api_key` genérico. Detectado por `exposed-secrets`. |
| Headers ausentes | toda resposta | Nenhuma rota seta `CSP`/`HSTS`/`X-Frame-Options`/`X-Content-Type-Options`. Detectado por `missing-headers`. |
| XSS refletido | `GET /search?term=` | `term` volta sem escape num `<html>`. **`scanner scan` ainda não detecta isso** — não existe check ativo `xss-reflected` implementado ainda (§7 do doc de projeto). O confirmer de `attack` já existe pra quando esse check chegar; dá pra exercitar essa rota manualmente com `curl` enquanto isso. |

`GET /items/{id}` é deliberadamente **seguro** (parâmetro vinculado, não
concatenado) — um controle pra notar se o scanner desse falso positivo nele.
`PUT`/`DELETE /items/{id}` existem só pra exercitar o gate de destrutivo
(ficam pulados por padrão, já que `configs/config.yaml` traz
`engine.test_destructive: false`).

### Subindo o lab

```bash
docker compose up -d --build
```

Isso sobe dois serviços: `db` (Postgres, com schema e seed em `lab/db/init.sql`)
e `lab-api` (porta `8080` no host, só sobe depois que `db` fica saudável). A
senha do usuário `admin` do lab já vem com um valor padrão
(`lab-pass-only-123`) que bate com o comentário de `configs/config.yaml` —
pra usar outra, exporte `LAB_PASSWORD` **antes** de subir o compose (ela é
lida como variável de ambiente do `docker compose`, não do scanner).

```bash
curl http://localhost:8080/health   # {"ok":true}
```

### Rodando o ciclo completo contra ele

`configs/config.yaml` já aponta pro lab (`localhost:8080`) sem precisar editar
nada — só exportar a mesma senha:

```bash
export LAB_PASSWORD='lab-pass-only-123'

scanner scan   --spec lab/openapi.yaml --config configs/config.yaml --out findings.json
scanner attack --in findings.json      --config configs/config.yaml --out confirmed.json
scanner report --in confirmed.json     --out report.html
```

O `scan` deve achar `sqli-boolean` em `/items`, `exposed-secrets` (2x) em
`/debug` e `missing-headers` em todas as rotas passíveis de baseline. O
`attack` deve confirmar a suspeita de SQLi e, contra o Postgres real, extrair
o nome do banco (`labapi`) via `UNION SELECT` — dá pra conferir em
`confirmed.json` sem precisar confiar só no texto deste README. Abra
`report.html` num navegador pra ver o resultado consolidado.

### Derrubando o lab

```bash
docker compose down -v   # -v também remove o volume do Postgres
```

---

## Arquitetura

Hexagonal leve (ports/adapters), para que os checks sejam testáveis contra um
`HTTPClient` falso, sem rede real.

```
cmd/scanner/          CLI e composition root — único lugar que decide os adapters
internal/
  ports/              interfaces: HTTPClient, Reporter, Store
  adapters/
    httpclient/       cliente HTTP real; é aqui que o ScopeGuard é aplicado
    openapi/          parser de spec OpenAPI 3 → []Endpoint
    config/           leitura e validação do config.yaml
  core/
    model/            Endpoint, Check, Finding, Evidence
    engine/           coleta de baseline + worker pool + rate limiter
    auth/             login automático + re-auth em 401
    scope/            ScopeGuard (allowlist de hosts)
  checks/             um arquivo por check, auto-registro via init()
    registry.go       RegisterCheck + resolução de checks.enabled
    headers.go        missing-headers (passivo)
    secrets.go        exposed-secrets (passivo)
    sqli.go           sqli-boolean (ativo)
    patterns/         regexes de detecção (secrets), via go:embed
    payloads/         payloads de ataque (sqli), via go:embed
  attack/             confirmers de PoC pro estágio attack, mesmo padrão init()
    attack.go         Register + dispatch por CheckName
    sqli.go           sqli-boolean: re-verificação + extração via UNION
    xss.go            xss-reflected: reflexão de marcador fresco
  envexpand/          expansão de ${VAR} compartilhada
  report/             template HTML (go:embed) + writer JSON
configs/              config.yaml de exemplo
lab/                  API vulnerável de estudo (módulo Go separado) + spec + init.sql
docker-compose.yml    sobe lab/ atrás de um Postgres real — ver §Lab acima
```

Detalhes de projeto e justificativas em [`doc/security-scanner-projeto.md`](doc/security-scanner-projeto.md).

---

## Testes

```bash
go test ./...              # todos os testes
go test ./... -race        # detector de race
go test ./... -cover       # cobertura
go vet ./...               # análise estática
golangci-lint run ./...    # lint (errcheck, bodyclose, errorlint, staticcheck…)
```

Os testes não tocam a rede externa: checks rodam contra um `HTTPClient` falso
alimentado por `testdata/`, e os testes de autenticação usam `httptest.Server` em
loopback. Há testes dedicados para o `ScopeGuard` (host fora da allowlist é
bloqueado antes de virar conexão) e para o determinismo do parser.

Há testes de ponta a ponta (`cmd/scanner/pipeline_test.go`) que montam a pilha
inteira — ScopeGuard, autenticação, rate limiter, coleta e check real — contra um
`httptest.Server`, e verificam entre outras coisas que a coleta nunca envia um método
inseguro, que endpoint destrutivo não é tocado, e que dois scans do mesmo alvo
produzem arquivos byte a byte idênticos. Um deles roda o ciclo `scan` → `attack`
completo contra um alvo com SQLi de verdade (simulado), incluindo a extração via
`UNION` — duas execuções de processo separadas, duas autenticações separadas,
como dois comandos `scanner` reais rodariam.

O CI (`.github/workflows/ci.yml`) roda gofmt, vet, golangci-lint, testes, race e cobertura.

---

## Licença

Ver [LICENSE](LICENSE).
