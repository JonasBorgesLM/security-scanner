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
    Kind          string              // "passive" | "active"
    RequiresAuth  bool
    AppliesTo     func(Endpoint) bool
}

type Check interface {
    Metadata() CheckMetadata
    Run(ctx context.Context, ep Endpoint, c ports.HTTPClient) ([]Finding, error)
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
2. **`Kind` passive/active** — engine não gasta request em check passivo.
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

### Contrato do engine

Implementado em `internal/core/engine`:

- **`BuildJobs(endpoints, checks, testDestructive)`** — cruza cada endpoint com os
  checks cujo `AppliesTo` aceita, e aplica a regra não-destrutiva: endpoint com
  `Destructive: true` não gera job nenhum sem opt-in explícito. Checks são pareados
  em ordem de nome, então a lista de jobs não depende da ordem em que o registry
  entregou.
- **`Run(ctx, jobs)`** — worker pool de `max_concurrency` workers consumindo de um
  channel. Devolve os resultados em ordem determinística (path, método, nome do
  check), independente de qual worker terminou primeiro.
- **Rate limiter como decorator de `ports.HTTPClient`**, não como portão por job.
  A cobrança é por *request*: check passivo que não faz request nenhum não gasta
  budget; check ativo que faz três é cobrado três vezes. Um único limiter é
  compartilhado por todos os workers, então concorrência não multiplica a taxa.
- **Shutdown gracioso** — cancelar o `ctx` (timeout global ou Ctrl+C) para o
  despacho de novos jobs, deixa os workers terminarem o que já pegaram, e devolve
  os resultados parciais junto com `ctx.Err()`. O `ctx` também chega aos checks,
  para que um request em voo se desenrole em vez de prender o shutdown atrás de
  uma conexão pendurada.
- **Check que entra em pânico vira erro no `Result`**, não derruba o scan inteiro —
  perder dez minutos de varredura por um bug num check seria pior do que reportá-lo.
- Erro de um check é registrado no `Result.Err` daquele job; `Run` só devolve erro
  para falha do run inteiro (cancelamento).

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
