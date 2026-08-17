# Security Scanner — Projeto, Arquitetura e Plano de Implementação

Ferramenta de estudo em Go para descobrir vulnerabilidades, confirmar via ataques controlados e gerar relatório final. Alvo exclusivo: sua própria API de laboratório (ambiente controlado).

---

## 1. Escopo e princípios

- **Uso restrito a ambiente próprio/autorizado.** O `ScopeGuard` (allowlist de hosts) é obrigatório e centralizado no cliente HTTP — nenhum request sai sem passar por ele.
- **Não-destrutivo por padrão.** Só testa métodos seguros (`GET`, `POST` de teste); `DELETE`/`PUT`/`PATCH` exigem opt-in explícito por endpoint.
- **Gentil por design.** Worker pool + rate limiter evitam self-DoS mesmo contra o próprio lab.
- **Auditável.** Cada estágio grava JSON versionado; scans são reproduzíveis e comparáveis.

---

## 2. Fluxo (subcomandos separados)

```
scanner scan   --spec openapi.yaml --config config.yaml --out findings.json
scanner attack --in findings.json  --config config.yaml --out confirmed.json
scanner report --in confirmed.json --out report.html
```

- **scan** — importa rotas do OpenAPI, autentica, roda checks (passivos + suspeitas ativas), grava `findings.json` (`Confirmed: false`).
- **attack** — reproduz cada suspeita com prova de conceito não-destrutiva, grava `confirmed.json`.
- **report** — consolida em HTML + JSON, com resumo executivo por severidade.

Arquivos intermediários são o contrato entre estágios: versionáveis no git, revisáveis manualmente antes do `attack`, executáveis em máquinas diferentes.

---

## 3. Arquitetura

**Hexagonal leve** (`ports` / `adapters`) para testar checks sem rede real.

```
security-scanner/
├── cmd/scanner/main.go            # CLI + composition root: scan | attack | report
├── internal/
│   ├── ports/                     # interfaces: HTTPClient, Reporter, Store
│   ├── adapters/
│   │   ├── httpclient/            # cliente real + ScopeGuard middleware
│   │   ├── openapi/               # parser de spec → []Endpoint
│   │   └── config/                # leitura + validação do config.yaml
│   ├── core/
│   │   ├── model/                 # Endpoint, Finding, Evidence, Report
│   │   ├── engine/                # worker pool + rate limiter + orquestração
│   │   ├── auth/                  # login automático + re-auth em 401
│   │   └── scope/                 # ScopeGuard
│   ├── checks/                    # cada check num arquivo, auto-registro via init()
│   │   ├── registry.go
│   │   ├── headers.go             # passivo
│   │   ├── secrets.go             # passivo
│   │   ├── sqli.go                # ativo
│   │   └── xss.go                 # ativo
│   ├── envexpand/                 # expansão de ${VAR} compartilhada
│   └── report/                    # templates HTML + writer JSON
├── payloads/                      # go:embed — sqli.txt, xss.txt
├── configs/
│   └── config.yaml                # exemplo comentado (escopo incluso, sem scope.yaml)
└── testdata/                      # specs e responses fake p/ testes
```

**Composition root.** `cmd/scanner` é o único lugar que escolhe adapters concretos.
Os pacotes de `core/` recebem um `ports.HTTPClient` e, por construção, não podem
verificar qual implementação chegou — então a garantia de que todo mundo recebeu o
cliente com `ScopeGuard` mora ali, e só ali. Entregar um `*http.Client` cru a
qualquer componente desligaria a fronteira de segurança sem quebrar compilação nem
teste.

### Decisões-chave (validadas)

| Decisão | Escolha | Motivo |
|---|---|---|
| Organização | Hexagonal leve | Testabilidade determinística sem rede |
| Concorrência | Worker pool + `x/time/rate` | Evita self-DoS; padrão de scanners reais |
| Extensibilidade | Registry via `init()` + metadados | Idiomático (como `database/sql` drivers) |
| Estágios | Arquivos JSON versionados (`schema_version`) | Auditoria e composição estilo Unix |
| Segurança | `ScopeGuard` como middleware central | Segurança por design, não por convenção |
| Storage | JSON em disco | YAGNI — sem DB por enquanto |
| Payloads | `go:embed` de arquivos | Estende sem recompilar a lógica |

---

## 4. Modelo de dados

```go
type Endpoint struct {
    Method         string
    Path           string
    Parameters     []Parameter
    RequiresAuth   bool
    SecurityScheme string
    Destructive    bool   // DELETE/PUT/PATCH → pulado sem opt-in
}

type CheckMetadata struct {
    Name          string
    OWASPCategory string
    Severity      string
    Kind          string              // KindPassive | KindActive
    RequiresAuth  bool
    AppliesTo     func(Endpoint) bool
}

// Response é a resposta capturada na coleta inicial, lida inteira em
// memória para que vários checks inspecionem a mesma sem refazer o request.
type Response struct {
    StatusCode int
    Headers    http.Header
    Body       []byte
    Duration   time.Duration
}

// Target é para onde o check aponta: o endpoint mais a baseline coletada.
type Target struct {
    Endpoint    Endpoint
    Baseline    *Response   // nil se a coleta falhou
    BaselineErr error
}

type Check interface {
    Metadata() CheckMetadata
    Run(ctx context.Context, t Target, c ports.HTTPClient) ([]Finding, error)
}

type Finding struct {
    ID            string
    CheckName     string
    Endpoint      Endpoint
    Severity      string
    OWASPCategory string
    Request       CapturedRequest   // request COMPLETO p/ o attack reproduzir
    Evidence      Evidence
    Confirmed     bool
}

type CapturedRequest struct {
    Method  string
    URL     string
    Headers map[string]string
    Body    string
    InjectedParam string
    Payload       string
}

type Evidence struct {
    BaselineResponse string        // resposta "limpa" p/ comparar (anti-falso-positivo)
    ResponseSnippet  string
    ResponseTime     time.Duration
    StatusCode       int
}
```

---

## 5. Correções incorporadas no planejamento

1. **Payloads em `go:embed`** — não hardcoded; estende sem tocar na lógica.
2. **`Kind` passive/active** — engine não gasta request em check passivo; ele recebe a resposta da coleta inicial e um cliente que recusa requests.
3. **`CapturedRequest` completo no Finding** — `attack` consegue reproduzir a suspeita.
4. **Baseline anti-falso-positivo** — repete request limpo p/ medir ruído (timestamp, CSRF token) antes de comparar em SQLi boolean-based.
5. **Flag `Destructive`** — métodos destrutivos pulados por padrão; opt-in explícito.
6. **Segredos via env** — `config.yaml` suporta `${LAB_PASSWORD}` p/ não commitar credencial.
7. **Context + timeout global + graceful shutdown** — `--timeout` e `Ctrl+C` cancelam o pool limpo.
8. **Re-auth em 401** — re-loga uma vez antes de marcar falha; rotas com login falho viram "skipped", nunca "vulnerável".

---

## 6. Config

Formato implementado em `internal/adapters/config`. O arquivo de exemplo comentado
vive em `configs/config.yaml` — **não existe `scope.yaml` separado**, o escopo é a
seção `scope:` deste mesmo arquivo.

```yaml
schema_version: 1
target:
  base_url: http://localhost:8080
scope:
  allowed_hosts: ["localhost:8080", "127.0.0.1:8080"]
auth:
  login_endpoint: /login
  method: POST                    # opcional, default POST
  credentials:
    username: admin
    password: ${LAB_PASSWORD}     # via env
  token_path: data.access_token
  token_header: Authorization     # opcional, default Authorization
  token_prefix: "Bearer "
engine:
  max_concurrency: 5
  requests_per_second: 10
  timeout: 5m
  test_destructive: false
checks:
  enabled: [missing-headers, exposed-secrets, sqli-boolean, xss-reflected]
```

### Regras de validação

`config.Load` acumula **todos** os problemas e falha uma vez só, listando cada um —
quem está corrigindo o arquivo vê a lista inteira em vez de descobrir um erro por
execução.

| Regra | Motivo |
|---|---|
| `schema_version` precisa ser exatamente `1` | Mudança futura de formato falha alto, não é lida errado em silêncio |
| `target.base_url` precisa ser URL absoluta | Sem host não há o que checar contra a allowlist |
| `scope.allowed_hosts` não pode ser vazia, sem entradas em branco | É a fronteira de segurança |
| **host do `target.base_url` ∈ `scope.allowed_hosts`** | Config incoerente faria o `ScopeGuard` bloquear o próprio alvo; falha na largada em vez de a cada request |
| `auth.login_endpoint`, `auth.token_path`, `credentials.username`, `credentials.password` obrigatórios | Sem eles não há login possível |
| `engine.max_concurrency`, `requests_per_second`, `timeout` > 0 | Zero desligaria pool ou rate limiter |
| `checks.enabled` não pode ser vazia | Um scan sem checks é ruído |

`auth.method` e `auth.token_header` são opcionais (default `POST` e `Authorization`).

### Expansão de `${VAR}`

Feita sobre os **valores escalares do YAML já parseado**, nunca sobre o texto cru —
assim um `${LAB_PASSWORD}` citado num comentário explicativo continua sendo
documentação, não uma referência a resolver. Variável não definida aborta com o nome
dela na mensagem (`envexpand.MissingVarsError` traz a lista completa, acessível via
`errors.AsType`), em vez de mandar o literal `${VAR}` como credencial para o alvo.

### Registry de checks

Implementado em `internal/checks/registry.go`, no padrão dos drivers de
`database/sql`: cada check se auto-registra num `init()`, então adicionar um check é
adicionar um arquivo — não há lista central para manter em sincronia.

- **`RegisterCheck(c)`** entra em pânico com check nil, nome vazio, `Kind`
  desconhecido ou nome duplicado. Todos são erros de programação em código próprio,
  detectáveis no instante em que o binário sobe — devolver `error` de dentro de um
  `init()` não daria a ninguém como tratar.
- **`Enabled(names)`** resolve o `checks.enabled` do config. Nome desconhecido é
  **erro**, listando os disponíveis — um typo no `config.yaml` desabilitaria um check
  em silêncio e produziria um relatório limpinho que simplesmente nunca o executou.
- **`All()` / `Names()`** devolvem em ordem de nome.

O engine **não** importa o registry: recebe `[]model.Check` já resolvido. Isso mantém
o engine testável sem estado global e preserva a direção das dependências
(`core/` não depende de `checks/`). Quem costura os dois é o composition root.

### Contrato do engine

Implementado em `internal/core/engine`:

- **`Collect(ctx, endpoints)`** — a *coleta inicial*: um request por endpoint,
  paralelizado no pool e limitado pelo rate limiter, produzindo `[]Target` com a
  baseline de cada um. **Só envia método seguro** (GET/HEAD/OPTIONS): endpoint
  declarado como POST/PUT/PATCH/DELETE é sondado com GET, e a substituição fica
  registrada em `Response.ProbedMethod`. Uma fase chamada "coleta" não pode criar
  nem destruir nada no alvo, e os headers que os checks passivos olham são
  propriedade da rota, não do verbo. Parâmetros de path (`{id}`) são preenchidos com
  um placeholder; 404, 405 ou 400 continuam sendo baseline válida. Endpoint
  destrutivo **não é coletado** sem opt-in, então não custa request algum. Coleta
  que falha ainda devolve um `Target`, com `BaselineErr` no lugar da resposta.
  Cancelamento devolve o que já foi coletado **mais um erro** — o chamador não pode
  confundir coleta truncada com coleta completa.
- **`BuildJobs(targets, checks)`** — cruza cada target com os checks aplicáveis, e
  reaplica a regra não-destrutiva (invariante de segurança garantida num lugar só é
  uma refatoração de distância de não ser garantida em lugar nenhum). Dois filtros:
  `AppliesTo`, e `CheckMetadata.RequiresAuth` — um check que só faz sentido com
  sessão (IDOR e afins) não é pareado com rota pública. Checks são pareados em ordem
  de nome, então a lista de jobs não depende da ordem em que o registry entregou.
- **`Run(ctx, jobs)`** — worker pool de `max_concurrency` workers consumindo de um
  channel. Devolve os resultados em ordem dos jobs, independente de qual worker
  terminou primeiro.
- **Rate limiter como decorator de `ports.HTTPClient`**, não como portão por job.
  A cobrança é por *request*: check passivo que não faz request nenhum não gasta
  budget; check ativo que faz três é cobrado três vezes. Um único limiter é
  compartilhado por todos os workers, então concorrência não multiplica a taxa.
- **Check passivo recebe um cliente que recusa todo request** (`ErrPassiveCheckRequest`).
  "Passivo não toca a rede" passa a valer por construção, não por confiança em cada
  check. É isso que mantém o número de requests proporcional ao tamanho do spec, e
  não ao spec vezes o número de checks habilitados.
- **Shutdown gracioso** — cancelar o `ctx` (timeout global ou Ctrl+C) para o
  despacho de novos jobs, deixa os workers terminarem o que já pegaram, e devolve
  os resultados parciais junto com `ctx.Err()`. O `ctx` também chega aos checks,
  para que um request em voo se desenrole em vez de prender o shutdown atrás de
  uma conexão pendurada.
- **Check que entra em pânico vira erro no `Result`**, não derruba o scan inteiro —
  perder dez minutos de varredura por um bug num check seria pior do que reportá-lo.
  Pânico fora de um check (na coleta, digamos) é contido pelo pool: aquele item some
  do resultado e a fase se reporta incompleta.
- **`Run` carimba o que já sabe em cada `Finding`**: `Endpoint`, `CheckName`,
  `Severity`, `OWASPCategory` e um `ID` determinístico. Assim nenhum check repete
  metadado que já declarou — e nenhum pode esquecer o `Endpoint`, que é justamente o
  que o estágio `attack` precisa para reproduzir.
- **Check que não consegue concluir devolve `model.Skippedf(...)`** e vira
  `Result.Skipped` com o motivo, nunca finding e nunca erro. Rota mostrada como limpa
  sem ter sido examinada é pior que rota assumidamente não examinada.
- Erro de um check é registrado no `Result.Err` daquele job; `Run` só devolve erro
  quando algum job ficou sem rodar.

O login/re-auth do `Authenticator` fica *abaixo* do limiter e portanto não é
limitado por ele — decisão consciente: logins são raros e já colapsados num único
in-flight pelo próprio `Authenticator`.

### Contrato de autenticação

Implementado em `internal/core/auth`:

- Login no `login_endpoint`, token extraído por `token_path` (notação de ponto sobre
  objetos JSON; sem indexação de array) e injetado em `token_header` com `token_prefix`.
- **Re-auth em 401, exatamente uma vez.** Se o retry ainda devolver 401, a resposta
  401 é repassada como resposta válida — cabe à camada de checks marcar a rota como
  `skipped`, nunca como "vulnerável".
- Se o próprio re-login falhar, o erro envolve `auth.ErrReAuthFailed` (testável com
  `errors.Is`), distinguindo "auth quebrada" de "rota realmente não autorizada".
- 401s concorrentes do worker pool colapsam num **único** re-login (contador de
  geração + mutex), em vez de um login por request em voo.
- Requests com corpo precisam ser reexecutáveis (`GetBody`), senão o retry pós-re-auth
  é rejeitado com erro explícito em vez de reenviar corpo vazio.

---

## 7. Ordem de implementação (casos de teste)

| Ordem | Check | Kind | Por quê |
|---|---|---|---|
| 1 | Headers ausentes | passivo | Zero ambiguidade; valida o pipeline inteiro |
| 2 | Secrets expostos | passivo | Só pattern matching; sem ataque |
| 3 | SQLi boolean-based | ativo | 1º ataque real; exercita baseline |
| 4 | XSS refletido | ativo | Injeta marcador, verifica reflexão sem escape |
| (5) | IDOR | ativo | Requer relação usuário↔recurso (fase 2) |
| (6) | JWT fraco (`alg:none`) | ativo | Validação de assinatura (fase 2) |

---

## 8. Testes

- **Unit** — cada check contra `HTTPClient` fake com responses de `testdata/`; sem rede.
- **Baseline** — teste dedicado provando que conteúdo dinâmico não vira falso-positivo.
- **ScopeGuard** — teste provando que host fora da allowlist é bloqueado (segurança do scanner).
- **Integração** — opcional, contra a API vulnerável de lab via Docker Compose.
