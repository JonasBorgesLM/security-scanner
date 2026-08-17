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
  lista é rejeitado **antes de a conexão ser aberta**.
- O scanner **se recusa a iniciar** se o host do `target.base_url` não estiver na
  allowlist — configuração incoerente falha cedo, com mensagem explícita.
- **Não-destrutivo por padrão:** endpoints `DELETE`/`PUT`/`PATCH` são pulados a menos
  que `engine.test_destructive: true` seja definido explicitamente.
- **A coleta inicial só usa métodos seguros.** Um endpoint declarado como `POST` é
  sondado com `GET` — a fase que monta a baseline nunca cria nem destrói nada no alvo.
- **Gentil por design:** worker pool + rate limiter evitam derrubar o próprio alvo.

---

## Requisitos

- Go 1.26 ou superior (veja `go.mod`)

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
| `auth.login_endpoint` | Rota de login, resolvida contra o `base_url` |
| `auth.credentials.username` / `password` | Credenciais do lab |
| `auth.token_path` | Caminho em notação de ponto até o token no JSON de resposta |
| `engine.max_concurrency` | Tamanho do worker pool (> 0) |
| `engine.requests_per_second` | Limite de taxa (> 0) |
| `engine.timeout` | Deadline global da execução, ex. `5m` |
| `checks.enabled` | Lista de checks a executar |

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
scanner report --in confirmed.json --out report.html
```

- **`scan`** — importa as rotas do OpenAPI, autentica no alvo, roda os checks e grava
  `findings.json` (suspeitas, `confirmed: false`).
- **`attack`** — reproduz cada suspeita com uma prova de conceito não-destrutiva e
  grava `confirmed.json`.
- **`report`** — consolida em HTML + resumo por severidade.

### Estado atual

O projeto está em construção. Hoje:

| Estágio | Estado |
|---|---|
| `scan` | **Funcional.** Importa o spec, autentica, coleta uma baseline por endpoint, roda os checks habilitados e grava `findings.json`. |
| `attack` | Não implementado (sai com erro e código 1) |
| `report` | Não implementado (sai com erro e código 1) |

Checks implementados:

| Check | Tipo | O que reporta |
|---|---|---|
| `missing-headers` | passivo | Cabeçalhos de segurança ausentes na resposta (`X-Content-Type-Options`, `Content-Security-Policy`, `Referrer-Policy`, e `Strict-Transport-Security` só sobre HTTPS) |

Um nome desconhecido em `checks.enabled` aborta a execução antes de qualquer
request — um typo não desabilita um check em silêncio.

Exemplo de execução do `scan`:

```console
$ export LAB_PASSWORD='...'
$ scanner scan --spec openapi.yaml --config configs/config.yaml
target:     http://localhost:8080
scope:      [localhost:8080 127.0.0.1:8080]
spec:       openapi.yaml
endpoints:  6 (5 require auth, 2 destructive)
checks:     missing-headers
            2 destructive endpoint(s) will be skipped (engine.test_destructive is false)

wrote findings.json (9 findings, 0 skipped, 0 failed)
```

Endpoints que não puderam ser examinados aparecem como `skipped`, com o motivo —
nunca como "limpos".

Ordem de implementação dos checks: headers ausentes (passivo) → secrets expostos
(passivo) → SQLi boolean-based (ativo) → XSS refletido (ativo) → IDOR / JWT fraco
(fase 2). Ver `doc/security-scanner-projeto.md` §7.

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
  envexpand/          expansão de ${VAR} compartilhada
  report/             templates HTML + writer JSON
payloads/             wordlists carregadas via go:embed
configs/              config.yaml de exemplo
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

Há um teste de ponta a ponta (`cmd/scanner/pipeline_test.go`) que monta a pilha
inteira — ScopeGuard, autenticação, rate limiter, coleta e check real — contra um
`httptest.Server`, e verifica entre outras coisas que a coleta nunca envia um método
inseguro, que endpoint destrutivo não é tocado, e que dois scans do mesmo alvo
produzem arquivos byte a byte idênticos.

O CI (`.github/workflows/ci.yml`) roda gofmt, vet, golangci-lint, testes, race e cobertura.

---

## Licença

Ver [LICENSE](LICENSE).
