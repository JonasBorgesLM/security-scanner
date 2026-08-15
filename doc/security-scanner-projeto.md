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
├── cmd/scanner/main.go            # CLI: scan | attack | report
├── internal/
│   ├── ports/                     # interfaces: HTTPClient, Reporter, Store
│   ├── adapters/
│   │   ├── httpclient/            # cliente real + ScopeGuard middleware
│   │   └── openapi/               # parser de spec → []Endpoint
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
│   └── report/                    # templates HTML + writer JSON
├── payloads/                      # go:embed — sqli.txt, xss.txt
├── configs/
│   ├── config.yaml
│   └── scope.yaml
└── testdata/                      # specs e responses fake p/ testes
```

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

## 6. Config (rascunho)

```yaml
schema_version: 1
target:
  base_url: http://localhost:8080
scope:
  allowed_hosts: ["localhost:8080", "127.0.0.1:8080"]
auth:
  login_endpoint: /login
  method: POST
  credentials:
    username: admin
    password: ${LAB_PASSWORD}     # via env
  token_path: data.access_token
  token_header: Authorization
  token_prefix: "Bearer "
engine:
  max_concurrency: 5
  requests_per_second: 10
  timeout: 5m
  test_destructive: false
checks:
  enabled: [missing-headers, exposed-secrets, sqli-boolean, xss-reflected]
```

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
