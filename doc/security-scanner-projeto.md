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
scanner report --in confirmed.json --out report.html [--json report.json]
```

- **scan** — importa rotas do OpenAPI, autentica, roda checks (passivos + suspeitas ativas), grava `findings.json` (`Confirmed: false`). **Feito.**
- **attack** — reproduz cada suspeita com prova de conceito não-destrutiva, grava `confirmed.json`. **Feito** — `internal/attack`, §7 abaixo.
- **report** — lê `confirmed.json`, consolida em HTML (`html/template`) + JSON, com resumo executivo por severidade. **Feito** — `internal/report`. Não toca a rede: só lê o arquivo de entrada e renderiza.

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
│   │   ├── patterns/secrets.txt   # regexes de detecção, go:embed
│   │   ├── sqli.go                # ativo
│   │   ├── payloads/sqli.txt      # payloads de ataque, go:embed
│   │   └── xss.go                 # ativo
│   ├── attack/                    # confirmers de PoC p/ o estágio attack, mesmo padrão init()
│   │   ├── attack.go              # Confirmer, Register, Run
│   │   ├── sqli.go                # sqli-boolean: re-verifica + extrai via UNION
│   │   └── xss.go                 # xss-reflected: reflexão de marcador fresco
│   ├── envexpand/                 # expansão de ${VAR} compartilhada
│   └── report/                    # templates HTML + writer JSON
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
| 1 | Headers ausentes | passivo | **Feito** — `internal/checks/headers.go`. Zero ambiguidade; valida o pipeline inteiro |
| 2 | Secrets expostos | passivo | **Feito** — `internal/checks/secrets.go`. Só pattern matching; sem ataque |
| 3 | SQLi boolean-based | ativo | **Feito** — `internal/checks/sqli.go`. 1º ataque real; exercita medição de ruído |
| 4 | XSS refletido | ativo | Injeta marcador, verifica reflexão sem escape |
| (5) | IDOR | ativo | Requer relação usuário↔recurso (fase 2) |
| (6) | JWT fraco (`alg:none`) | ativo | Validação de assinatura (fase 2) |

---

### Contrato do `sqli-boolean`

Implementado em `internal/checks/sqli.go` — o primeiro check ativo, e o primeiro
que não lê o corpo de `Target.Baseline`.

- **Payloads em pares `verdadeiro`/`falso`**, embutidos de
  `internal/checks/payloads/sqli.txt` via `go:embed` (formato
  `nome ||| payload-verdadeiro ||| payload-falso`, um por linha). Arquivo
  malformado entra em pânico no `init()` — é dado próprio embutido no binário,
  então é erro de build, não condição de runtime.
- **`AppliesTo`** restringe jobs a endpoints com pelo menos um parâmetro de
  `query` ou `path` — header e body ficam fora de escopo por ora (body
  precisaria saber o formato do payload, não só uma string pra substituir).
- **Medição de ruído ANTES de injetar**: repete um request benigno (valor
  fixo `"1"`, mesmo parâmetro, mesmo endpoint) `sqliNoiseSamples` (3) vezes e
  usa a maior diferença de tamanho de corpo entre essas repetições como piso
  de ruído — isso mede variação de conteúdo dinâmico (timestamp, nonce, CSRF
  token) que nada tem a ver com o parâmetro injetado.
- **Só marca suspeita se `diff(verdadeiro, falso) > ruído`**, nunca um limiar
  fixo — "ruído" é propriedade do alvo, não uma constante do código.
  Outros parâmetros do endpoint são preenchidos com o mesmo valor benigno
  durante o teste, pra um parâmetro obrigatório vazio não confundir o
  resultado.
- **Não lê `Target.Baseline` como conteúdo** — aquela baseline foi coletada
  sem nenhum parâmetro preenchido, então não serve pra responder "mudar este
  parâmetro muda a resposta?". Reusa só `Target.Baseline.URL` pra descobrir
  scheme/host do alvo, já que nada mais no contrato de `Check` carrega isso.
  Sem baseline (coleta falhou), o check devolve `Skippedf` — não tem como
  saber pra onde mandar o request.
- **`CapturedRequest` completo**: `Method`, `URL` (já com o payload
  verdadeiro codificado, pronta pra reproduzir com `curl` ou pelo estágio
  `attack`), `InjectedParam`, `Payload`.

---

### Contrato do `attack`

Implementado em `internal/attack` — lê `findings.json`, tenta confirmar cada
`Finding` não confirmado, grava `confirmed.json`. É um processo **separado** do
`scan`: não herda sessão, não herda estado, autentica de novo do zero contra o
mesmo `config.yaml`.

- **Registry por `CheckName`**, mesmo padrão `init()` + `RegisterCheck` de
  `internal/checks`: cada check com PoC implementa `attack.Confirmer` (método
  `CheckName() string` + `Confirm(ctx, Finding, HTTPClient) (Finding, error)`) e
  se registra via `attack.Register`. `attack.Run` despacha cada finding pelo
  nome; sem confirmer registrado pra aquele `CheckName`, o finding passa
  **inalterado** pro `confirmed.json`, listado como `skipped` — nunca promovido a
  `Confirmed: true` sem verificação de verdade. `missing-headers` e
  `exposed-secrets` caem nesse caso hoje: são observação direta de uma única
  resposta já coletada, não têm o que "reproduzir".
- **Gate `Destructive` reaplicado**, independente do que o `scan` já decidiu —
  `attack` é invocação de processo separada, não pode assumir que aquela decisão
  ainda vale.
- **`sqli-boolean`**: dois passos.
  1. Re-verifica o MESMO comparativo verdadeiro/falso do check, medindo ruído de
     novo agora (não confia no que o `scan` mediu antes — o alvo pode ter mudado).
     Só essa reprodução já é o suficiente pra `Confirmed: true`.
  2. Só então, tenta extrair **o nome do banco via `UNION SELECT`** — leitura
     pura, nunca escrita. Descobre a contagem de colunas testando 1 até
     `sqliMaxColumns` (6), envolvendo uma constante em `CONCAT('ATTACKPOC_','OK','_ENDPOC')`
     na última coluna — achar o marcador na resposta prova contagem certa,
     `CONCAT` funciona nesse motor, e a última coluna aparece na resposta, tudo
     num request só. Encontrada a contagem, tenta candidatos
     (`database()`, `current_database()`, `DB_NAME()`, `sqlite_version()`) na
     mesma posição. **Best-effort**: se a extração falhar (motor desconhecido),
     o finding continua confirmado pela reprodução booleana — só a nota de
     evidência muda pra dizer que a extração não funcionou.
  3. `FalsePayloadFor` (exportada de `internal/checks/sqli.go`) reconstrói o
     payload falso pareado ao verdadeiro do `Finding`, reusando o MESMO
     `payloads/sqli.txt` — uma fonte de verdade só, sem duplicar o parser.
- **`xss-reflected`**: reenvia com um marcador **novo, gerado agora**
  (`crypto/rand`, não o payload original do scan) — evita cache e distingue
  "refletiu sem escape" (confirmado) de "refletiu mas escapado" (não
  confirmado, mas dito explicitamente — não é o mesmo que "não refletiu").
- **`withInjectedValue`** reescreve a URL capturada trocando só o valor do
  parâmetro injetado, sem precisar saber a lista de parâmetros do endpoint —
  funciona pra query (via `net/url`) e pra path (substring na forma
  *decodificada* de `u.Path`; comparar contra a forma escapada foi um bug real
  encontrado pelos próprios testes deste pacote — `url.URL` guarda o path
  decodificado e só usa `RawPath` quando ele bate com o `Path` atual).
- **Sonda com o método real do endpoint, não força GET.** Segue o princípio
  já declarado em §1 ("só testa métodos seguros: GET, POST de teste") —
  DELETE/PUT/PATCH nunca chegam neste check (o gate não-destrutivo do engine
  já filtra `Destructive` antes de qualquer job existir); POST fica em
  escopo de propósito. Tradeoff consciente: um endpoint POST que acaba não
  sendo vulnerável ainda absorve até `sqliNoiseSamples + 2×pares` requests
  por parâmetro até ser descartado — se aquela rota cria um recurso a cada
  chamada, sobra dado de teste real (modesto, com rate limit) no lab. Forçar
  GET evitaria isso, mas um servidor que roteia estrito por método
  responderia 404 em toda sonda e o check "limparia" uma rota que nunca
  chegou a exercitar de verdade — um jeito de falhar pior do que umas linhas
  extra no banco do próprio lab do operador.

---

### Contrato do `report`

Implementado em `internal/report` — lê `confirmed.json` e grava `report.html` +
`report.json`. É o único estágio que não toca a rede: nada aqui constrói ou
envia um request, então não precisa de `ScopeGuard`, cliente HTTP nem
autenticação.

- **`html/template`, nunca `text/template`.** `Evidence` e `Request` carregam
  texto potencialmente influenciado por quem foi atacado — payload de SQLi,
  marcador de XSS refletido, trecho cru de resposta. `html/template`
  escapa por contexto automaticamente; renderizar isso com `text/template`
  tornaria o próprio relatório um sink de XSS ao abrir no navegador.
  `TestWriteHTML_EscapesAttackerControlledContent` prova isso injetando um
  `<script>` real num finding de exemplo e checando que ele sai como
  `&lt;script&gt;`, nunca como tag executável.
- **Template embutido via `go:embed`** (`internal/report/template.html`),
  mesmo padrão de `patterns/secrets.txt` e `payloads/sqli.txt`: fica ao lado
  do pacote que o usa, parseado uma vez em `init()` — template malformado é
  erro de build, não condição de runtime.
- **Ordenação determinística**: `Build` ordena por severidade (crítico → alto
  → médio → baixo → desconhecido), depois confirmado antes de não-confirmado,
  depois por `CheckName`, `Endpoint.Path` e `ID` como desempate — nunca pela
  ordem de descoberta do `scan`. Isso vale tanto pro HTML quanto pro
  `report.json`, então os dois arquivos mostram os achados na mesma ordem e
  `report.json` fica byte-idêntico entre duas execuções sobre o mesmo
  `confirmed.json`, mantendo o invariante de determinismo do pipeline.
- **Resumo executivo** conta achados por severidade e, dentro de cada
  severidade, quantos já foram confirmados por PoC — a distinção importa: um
  `high` confirmado pesa muito mais que um `high` ainda só suspeito.
- **Recomendação de correção vive só no pacote `report`** (mapa
  `CheckName` → texto), não em `model.Finding`: é conteúdo de apresentação,
  não faz parte do schema JSON versionado que `scan` e `attack` populam.
  Check sem entrada no mapa recebe um texto genérico de fallback em vez de
  ficar em branco.
- **`--json` é opcional**: por padrão deriva de `--out` trocando a extensão
  (`report.html` → `report.json`), mas aceita um caminho explícito.

---

## 8. Testes

- **Unit** — cada check contra `HTTPClient` fake com responses de `testdata/`; sem rede.
- **Baseline** — teste dedicado provando que conteúdo dinâmico não vira falso-positivo.
- **ScopeGuard** — teste provando que host fora da allowlist é bloqueado (segurança do scanner).
- **Integração** — opcional, contra a API vulnerável de lab via Docker Compose:
  `lab/` (módulo Go próprio) + Postgres real, subidos por `docker-compose.yml`
  na raiz do repo. Cobre as quatro classes deste projeto — SQLi boolean-based
  com extração via `UNION SELECT` de verdade, secrets expostos, headers
  ausentes, e XSS refletido (este último sem check ativo ainda; existe pro
  `attack`'s confirmer e pro dia em que `xss-reflected` for implementado).
  `GET /items/{id}` é parametrizado de propósito — um controle negativo pra
  notar um falso positivo. Não faz parte de `go test ./...`; é um alvo pra
  rodar o ciclo `scan → attack → report` manualmente. Ver README.md §Lab.
