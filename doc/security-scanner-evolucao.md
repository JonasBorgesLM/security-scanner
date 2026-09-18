# Security Scanner — Evolução: auditoria, decisões e roadmap

Complementa `security-scanner-projeto.md`, que continua sendo a fonte de
verdade da arquitetura **atual**. Este documento registra a auditoria feita
sobre o código implementado, as decisões estruturais tomadas a partir dela, e
a ordem de evolução que resulta. Nada aqui descreve código que já existe.

---

## 1. A régua

O scanner responde **uma** pergunta: *"este comportamento observável está
correto do ponto de vista de segurança?"* — sob quatro invariantes:

1. **Correção acima de volume** — afirma pouco, com precisão.
2. **Só afirma com prova** — piso de ruído no scan, confirmer separado no attack.
3. **Gentil por design** — ScopeGuard + rate limiter + gate não-destrutivo.
4. **Auditável e comparável** — a saída de cada estágio é revisável à mão e
   duas execuções sobre o mesmo alvo são comparáveis item a item.

A quarta invariante mudou de redação — a anterior prometia mais do que o
código entrega. Ver §4.3.

**Teste para qualquer função nova:** é uma pergunta de correção verificável,
provável de forma gentil, sobre algo observável de fora? Se exige estado
interno, volume, código-fonte, ou modificar o alvo — fica de fora (§7).

---

## 2. Correções ao desenho proposto

Quatro pontos do mapa de evolução original não sobreviveram ao contato com o
código. Registrados aqui porque a conclusão sozinha se perde; o raciocínio é
o que evita refazer o mesmo erro.

### 2.1 Passivo não é sinônimo de gentil

`Target.Baseline` é **uma** resposta, obtida com **um** método, sem **nenhum**
header de request forjado. Qualquer check cuja pergunta seja *"o que acontece
se eu variar o request?"* é ativo por definição, por mais barato que seja.

| Check proposto como passivo | Realidade |
|---|---|
| `cors-misconfigured` | Middleware CORS correto só emite `Access-Control-Allow-Origin` quando há `Origin` no request. A baseline não manda `Origin` — passivamente só se pega o caso `ACAO: *` sempre-ligado, e a reflexão de origem fica invisível |
| `dangerous-http-methods` | `TRACE` só se detecta enviando TRACE; `Allow:` na prática só aparece em 405 ou em resposta a OPTIONS, não num 200 típico |
| `insecure-cookie-flags` | Genuinamente passivo, mas numa API JSON com Bearer token `Set-Cookie` tende a nunca aparecer |
| `cache-on-authenticated` | Genuinamente passivo e correto — a baseline **é** autenticada (`runScan` passa o `Authenticator` ao `engine.New`) |

Consequência: o bloco de checks de configuração deixa de ser "um arquivo novo
cada" e passa a depender de uma decisão de coleta. Ver §4.2.

### 2.2 Um check só tem uma identidade

`Authenticator.Do` injeta o token em **todo** request, incondicionalmente, e
fica *abaixo* do rate limiter na cadeia. Um check recebe um `ports.HTTPClient`
e não tem como mandar um request anônimo, nem como outro usuário.

Isso reposiciona `idor`: ele não é um caso isolado de alta complexidade, é o
**segundo** consumidor de uma capacidade cujo primeiro consumidor (§2.4) é
barato e mais valioso. Resolver identidade uma vez atende os dois.

### 2.3 `deps` e `rate-limit-bypass` estão fora da régua

- **`govulncheck`** lê `go.mod` e o código-fonte: é análise estática, que a
  régua exclui explicitamente. E consulta o banco de vulnerabilidades pela
  rede em tempo de execução, então duas rodadas sobre o mesmo código podem
  divergir. Continua valioso — mas como **passo de CI**, não como subcomando
  do scanner, e nunca misturado ao `findings.json`.
- **`rate-limit-bypass`** depende de timing e concorrência do alvo: o
  resultado não é comparável entre execuções. E "presença de 429 sob rajada"
  é um teste de carga em miniatura, que a régua também exclui. Se entrar,
  entra num canal de saída próprio, fora do contrato comparável.

### 2.4 O que faltava: `auth-required`

Para cada endpoint que o spec declara protegido, mandar o request **sem
token** e verificar que volta 401/403. Se voltar 200, é A01, critical, prova
trivial.

É o melhor item disponível do roadmap inteiro: determinístico, preto-e-branco,
sem piso de ruído, não-destrutivo por construção, e **não precisa de segundo
usuário** — o oráculo é a declaração do próprio spec. `Endpoint.RequiresAuth`
e `SecurityScheme` já são extraídos por `resolveSecurity` e hoje só servem
para decidir se vale logar.

### 2.5 Sinal antes de volume

`missing-headers` numa API que só devolve JSON reporta CSP e X-Frame-Options
em toda rota. Nenhum dos dois significa nada para uma resposta
`application/json` que browser nenhum renderiza como documento. É o mesmo modo
de falha que `exposed-secrets` já evita com o filtro de placeholder: um check
que as pessoas aprendem a ignorar leva junto os achados reais.

---

## 3. Auditoria do código atual

Estado geral: build, `vet` e testes verdes; cobertura 82–100% por pacote; CI
com gofmt/vet/lint/test/race. As invariantes de segurança estão *construídas*,
não só documentadas — `deniedClient` torna "passivo não toca a rede"
impossível de violar, `CheckRedirect` fecha o salto de redirect, `runPool`
preserva ordem de entrada em vez de ordenar depois.

O que segue é o que não está bem.

| # | Sev | Achado | Evidência | Issue |
|---|---|---|---|---|
| 1 | HIGH | Rotas skipped/failed nunca chegam ao relatório | `cmd/scanner/main.go:163,167`; `model/finding.go:44-47`; `report/report.go:105-115` | #12 |
| 2 | HIGH | "Byte-idêntico" só vale contra alvo estático | `checks/sqli.go:263-266`; `checks/xss.go` (`BaselineResponse`) | #13 |
| 3 | MEDIUM | Checks ativos limpam rotas POST que nunca exercitaram | `checks/sqli.go:322-356` (body `nil`), `sqli.go:163-171` | #28 |
| 4 | MEDIUM | Nenhum timeout por request | `adapters/httpclient/httpclient.go:38-39` | #15 |
| 5 | MEDIUM | ~~Falha de auth vira `failed`, não `skipped`~~ → **corrigido:** falha de auth *parcial* é descartada em silêncio | `checks/sqli.go`, `checks/xss.go`: `lastErr` descartado quando `tested > 0` | #16 |
| 6 | LOW | `ExtraHeaders` pode sobrescrever `Content-Type`, contra o próprio doc | `core/auth/auth.go:223-226` vs `auth.go:58-63` | #17 |
| 7 | LOW | `anyFieldSet` ignora `username_field` e `extra_headers` | `adapters/config/config.go:97-105` | #17 |
| 8 | LOW | `expandTree` engole erro que não seja `MissingVarsError` | `adapters/config/config.go:197-207` | #17 |
| 9 | LOW | ScopeGuard é comparação exata de string; allowlist por nome | `core/scope/scope.go:37` | #18 |
| 10 | LOW | Comentários obsoletos que contradizem o código | `checks/xss.go`; `attack/request.go:59-63`; `envexpand.go:4` | #18 |

### 3.1 Detalhe dos dois HIGH

**#1 — cobertura.** O `CLAUDE.md` afirma *"Skipped routes must reach the
report: showing a route as clean when it was never examined is worse than
admitting it could not be looked at"*, e `engine.Result.Skipped` repete no
doc comment. Na prática `summarise` devolve `skipped` e `failed`, `runScan`
escreve só `findings`, e as duas listas viram linhas de stderr descartadas.
`model.FindingsFile` não tem onde carregá-las.

Um scan em que o auth quebrou em 90% das rotas produz um `report.html`
indistinguível de um scan limpo de uma API saudável — só com menos findings.

É bloqueante para `scanner diff`: comparar o `findings.json` de ontem com o de
hoje reportaria `-resolvido` para uma rota que apenas não foi examinada hoje.
Um verde falso é o pior modo de falha possível para uma guarda de regressão.

**#2 — determinismo.** `sqli.go` embute no `Evidence` três valores medidos ao
vivo (piso de ruído, `diff` em bytes, trecho do corpo); `xss.go` embute o
trecho da baseline. Contra um alvo com timestamp, request-id ou contador, dois
scans idênticos produzem arquivos diferentes.

`TestScan_IsReproducible` passa porque `newLabServer` serve corpo estático —
o teste é honesto, mas não cobre a condição que a invariante precisa proteger.

**Confirmado empiricamente** (reprodutor em #13): contra um servidor vulnerável
que carrega um request-id de largura fixa em toda resposta, duas execuções do
`sqli-boolean` produzem findings com `evidence` diferente — e com **identidade
idêntica** (`ID`, URL e `payload` iguais). É a confirmação direta da regra de
§4.3: comparar por identidade funciona, comparar bytes não.

O achado 3 também foi confirmado por teste (reprodutor em #28): 15 sondas
gastas contra uma rota POST que exige body, todas rejeitadas com 400, zero
alcançando o caminho vulnerável, e `Run` devolvendo `(nil, nil)` — nem finding
nem skip.

### 3.1.1 Correção ao achado 5

O achado 5 foi enunciado errado e a correção fica registrada aqui, porque um
documento que só guarda a conclusão certa não ensina a desconfiar da errada.

**O que eu afirmei:** nenhum check mapeia `auth.ErrReAuthFailed` para
`model.Skippedf`, logo auth quebrado cai em `Result.Err`.

**O que a medição mostrou:** falha *total* de auth já vira `Skipped`, por dois
caminhos que a leitura não seguiu até o fim — `tested == 0` em `sqli`/`xss`, e
baseline nil quando a coleta falha. `errors.Is(err, model.ErrSkipped)` é
`true` nos três casos testados. **A invariante 6 estava de pé.**

**O defeito real, que só a medição achou:** o caso *parcial*. Com dois
parâmetros, um servindo e outro com auth quebrado:

```
findings=0  err=<nil>
requests servidos=18  recusados=6
```

Seis sondas recusadas, e `Run` devolve `(nil, nil)`. `lastErr` é preenchido e
descartado sempre que `tested > 0`. A rota consta **examinada e limpa** — o
mesmo modo de falha do achado 3 por outra porta.

A lição de método é a mesma do §3.3: leitura de código gera hipótese, não
achado. Esta ficou uma etapa inteira no documento com o enunciado invertido.

---

### 3.2 Limite que o ScopeGuard não cobre

A allowlist é **por nome de host**, não resolve IP. Não protege contra DNS
rebinding, e não normaliza caixa nem porta implícita (`LOCALHOST:8080` não
casa `localhost:8080`). Falha sempre fechado, então não é bypass — mas
`CLAUDE.md` chama ScopeGuard de *"the hard security boundary"* sem qualificar,
e um controle descrito como completo quando é parcial é pior que um ausente.
Correto para o modelo de ameaça ("não escanear a máquina de outro por
acidente"); o que faltava era dizer isso.

### 3.3 Execução ao vivo contra a `task-api`

A auditoria acima é leitura de código. Um scan real, medido com um proxy
contador entre o scanner e o alvo, mudou a ordem de grandeza do achado 1 e
revelou três causas que a leitura não pegava.

Alvo: `task-api` local, 30 endpoints no spec, 22 não-destrutivos, autenticado.

O instrumento é `tools/reqcount`, um proxy contador que fica entre o scanner
e o alvo e reporta quantos requests saíram e o que voltou. Ele existe porque
a saída do próprio scanner não pode dar esse número — a etapa inteira partiu
da constatação de que ele sub-reportava o que fazia, então medi-lo com ele
mesmo seria circular:

```
go run ./tools/reqcount -upstream http://localhost:8080 &
scanner scan --spec openapi.yaml --config config-pelo-proxy.yaml --out findings.json
kill -TERM %1
```

**Custo que isso tem:** rodando pelo proxy, o ScopeGuard passa a validar o
endereço *do proxy*, não o do alvo. A allowlist continua valendo — nada sai
para fora dela — mas o que ela garante vira "o scanner só falou com o proxy",
e o proxy fala com o que `-upstream` mandar. A fronteira que importa se mudou
para dentro de uma flag. É troca aceitável para uma medição deliberada contra
o próprio lab, e inaceitável para qualquer outra coisa.

```
TOTAL: 278 requests do scanner

GET  -> 200 :  10      <-- 4%
GET  -> 400 : 136
GET  -> 404 : 109
GET  -> 405 :   5
POST -> 200 :   1      (o login)
POST -> 400 :  17
```

Saída do scanner, integral:

```
wrote findings.json (0 findings, 0 skipped, 0 failed)
```

**11 de 278 requests obtiveram resposta útil**, e o arquivo diz `0 skipped, 0
failed`.

O contraste que torna isso difícil de enxergar sem medir: a `task-api` **é**
genuinamente bem endurecida — os quatro headers que `missing-headers` procura
estão presentes em toda resposta, então zero findings é honesto *para aquele
check*. Um relatório vazio e correto e um relatório vazio por cegueira são,
hoje, o mesmo arquivo. É exatamente por isso que o achado 1 é o item de maior
prioridade da etapa.

As três causas, cada uma com issue própria:

| Causa | Evidência | Issue |
|---|---|---|
| Sonda rejeitada (4xx) lida como resposta válida | `/v1/tasks?status=1` → 400; o **filler benigno** é rejeitado junto com o payload, então `measureNoise` mede o ruído de páginas de erro | #30 |
| Baseline de rota não-GET é página 405 | `/v1/auth/{logout,register,password}` → 405; passivos julgam a página de erro, e `ProbedMethod` é escrito e nunca lido | #31 |
| Rotas do spec ausentes no alvo | `/v1/links` → 36 sondas, 36× 404 | #32 |

A lição de método: **contra uma API bem construída, os checks ativos atuais não
concluem quase nada — e não dizem isso.** A régua do §1 diz "afirma pouco, com
precisão"; o que o scanner faz hoje é afirmar pouco sem precisão nenhuma, que é
outra coisa.

Nota sobre o achado 2: este scan não o exercita, porque sem nenhum finding não
há `evidence` para variar entre execuções. Os dois arquivos saem idênticos de
forma trivial. A confirmação do achado 2 é a de #13, por teste dedicado.

---

## 4. Decisões estruturais

Quatro decisões que valem para o projeto todo, não só para a etapa em que cada
uma é implementada. Cada uma registra a opção **não** tomada: a conclusão
sozinha é o que um leitor futuro vai questionar, o raciocínio é o que ele
precisa.

### 4.1 Cobertura entra no contrato — `schema_version: 2` *(Etapa 1, #12)*

`FindingsFile` ganha um bloco `coverage` ao lado de `findings`:

```json
{
  "schema_version": 2,
  "coverage": {
    "endpoints_total": 14,
    "checks_run": 42,
    "skipped": [
      { "check": "sqli-boolean",
        "endpoint": "POST /v1/tasks",
        "reason": "auth failed after re-auth" }
    ],
    "failed": []
  },
  "findings": [ ]
}
```

`attack` propaga a cobertura que recebeu e acrescenta a sua; `report` passa a
mostrar, ao lado do resumo executivo, o que **não** foi examinado.

**Opção não tomada:** um `coverage.json` separado, deixando o schema em 1. Sai
mais barato (zero mudança de contrato) mas mantém dois arquivos em sincronia
manual, e nada impede rodar `report` só com `findings.json` — o que reproduz
exatamente o verde falso de hoje. O custo do bump é pago uma vez; o do
arquivo opcional se paga em toda execução futura.

### 4.2 Probe set seguro na coleta *(implementado na Etapa 3, #14)*

`Collect` passa a obter, por endpoint, um conjunto **fixo e pequeno** de
respostas com métodos seguros:

| Probe | Request | Serve a |
|---|---|---|
| `baseline` | o de hoje, inalterado | tudo que já existe |
| `options` | OPTIONS na mesma URL | `dangerous-http-methods`, preflight CORS |
| `origin` | GET com `Origin:` sentinela | `cors-misconfigured` |

`Target.Baseline` permanece **exatamente** como está — invariantes 4 e 5
intactas — e ganha `Target.Probes` ao lado, com a mesma regra de leitura:
compartilhado por ponteiro entre checks concorrentes, portanto somente
leitura.

Custo: 3 requests por endpoint em vez de 1. Em contexto, `sqli-boolean` já
gasta `3 + 2×len(pairs)` requests **por parâmetro**; +2 por endpoint é ruído
diante disso. A propriedade que importa se mantém: requests proporcionais ao
tamanho do spec, não ao spec × número de checks.

**Opção não tomada:** cada check ativo manda o seu probe, via `sendProbe`.
Mais simples e sem mudança arquitetural, mas multiplica requests por check,
empurra três checks de configuração para `KindActive` sem necessidade, e faz
`sendProbe` — o caminho de *ataque* — ser usado por coisas que não atacam. A
escolha por (b) só se justifica porque há **três consumidores concretos hoje**,
não um hipotético; com um só, a duplicação seria mais barata.

**Não configurável.** O conjunto é fixo no código. Um probe set extensível por
YAML seria a porta de entrada para requests arbitrários fora do gate
não-destrutivo.

### 4.3 Determinismo: identidade separada de evidência *(Etapa 1, #13)*

A invariante 8 passa a ser enunciada em duas partes:

- **Identidade de um finding é determinística.** `ID` deriva só de
  check + método + path + discriminador, e nunca de nada medido no alvo.
  É por ela que `scanner diff` compara — nunca por bytes do arquivo.
- **Evidência é descritiva, não comparável.** Trechos de corpo, piso de ruído
  e diferenças em bytes são o que o humano lê para julgar o finding; variam
  com o alvo e isso é esperado.

O que continua proibido é wall-clock em finding que não seja sobre tempo
(`Evidence.ResponseTime`), porque isso varia sem que **nada** no alvo tenha
mudado.

`TestScan_IsReproducible` ganha um par que sirva corpo dinâmico e assegure a
estabilidade dos **IDs**, não do arquivo inteiro.

**Consequência para `exposed-secrets`:** seu discriminador é
`findingDiscriminator(p.name, len(findings))` — índice posicional dentro do
padrão. Se um de dois achados do mesmo padrão sumir, o ID do remanescente
muda e o diff reporta "1 removido + 1 novo" para uma remoção só. Precisa de um
discriminador estável antes do `diff`.

### 4.4 Timeout por request *(Etapa 1, #15)*

`httpclient.New` passa a aplicar um timeout por request, configurável em
`engine.request_timeout` (default modesto). Hoje o único limite é o ctx do run
inteiro: cinco rotas penduradas prendem os cinco workers até `engine.timeout`
disparar, e o scan inteiro se perde. Com a coleta triplicando requests, o
risco triplica junto.

---

## 5. O princípio que ordena o plano

A execução ao vivo (§3.3) separou os checks em dois grupos com destinos
diferentes, e essa divisão é o que ordena tudo abaixo:

| Oráculo do check | Sobrevive a input validado? | Exemplos |
|---|---|---|
| **Propriedade da resposta** (status, header) | **Sim** — um 400 de validação ainda não é um 401 | `auth-required`, `missing-headers`, `cache-on-authenticated`, `cors` |
| **Reflexão do payload** | **Não** — a validação rejeita a sonda antes de ela chegar a qualquer query | `sqli-boolean`, `xss-reflected` |

### Medido, não argumentado

A tabela acima era uma previsão quando foi escrita. Com o `auth-required`
implementado (#21), ela virou uma medição — mesmo alvo, mesma execução, os
cinco checks lado a lado:

| Check | Oráculo | Vereditos | Skips |
|---|---|---|---|
| `auth-required` | status code | **15** | 1 |
| `exposed-secrets` | corpo já coletado | 13 | 8 |
| `missing-headers` | headers já coletados | 13 | 8 |
| `sqli-boolean` | reflexão do payload | **0** | 8 |
| `xss-reflected` | reflexão do payload | **0** | 8 |

`auth-required` concluiu sobre **15 de 16** rotas que se aplicavam. Os dois
checks de injeção concluíram sobre **zero** — recusados pela validação antes
de alcançarem qualquer coisa, exatamente como o §3.3 previu.

E os 15 vereditos não são silêncio: cada um é a afirmação de que uma rota que
o spec declara protegida **de fato recusa** um request sem credencial,
verificada mandando um. É o primeiro "limpo" que este scanner já mereceu.

Um detalhe que custou menos do que eu temia: `POST /v1/auth/logout` e irmãs
receberam veredito mesmo sem body, porque autenticação roda antes de
validação — o 401 volta de qualquer jeito. A troca de "não mandar body"
custou um veredito, não quinze.

Duas consequências que o plano original não tinha como enxergar:

1. **`auth-required` é imune ao modo de falha do #30**, então é o primeiro
   check novo — não um item no meio da fila.
2. **`sqli`/`xss` não ganham nada com checks novos ao lado.** Precisam de #30 e
   #28 antes de valerem alguma coisa contra uma API real.

E a régua do §1 ganha um corolário que a medição tornou óbvio: *"afirma pouco,
com precisão"* não é o mesmo que afirmar pouco. Um scan que não conclui e não
diz que não concluiu afirma pouco **sem** precisão nenhuma.

---

## 6. O plano

Cinco etapas. Cada uma tem um critério de saída medível contra o baseline
levantado em §3.3 — 278 requests, 11 úteis, `0 skipped, 0 failed`.

### Etapa 1 — Honestidade

**Propriedade que a etapa compra:** a saída do scan distingue "limpo" de "não
examinado".

Nada depois disso vale enquanto ela não estiver de pé: todo relatório, diff e
gate construído sobre a saída atual herda a mentira por omissão.

| Issue | Item |
|---|---|
| #12 | Cobertura entra no contrato (`schema_version 2`) |
| #30 | Sonda rejeitada (4xx) vira `Skipped`, não silêncio |
| #31 | Baseline 405 por método substituído é declarada |
| #32 | Rota do spec ausente no alvo vira `Skipped` |
| #16 | Falha de auth vira `skipped`, não `failed` |
| #13 | Determinismo: identidade separada de evidência |
| #15 | Timeout por request |
| #17 | Três consertos pontuais (achados 6, 7, 8) |
| #18 | Limites do ScopeGuard + comentários obsoletos |
| #19 | `.gitignore` do binário + `govulncheck` no CI |

**Critério de saída:** rodar o mesmo scan da `task-api` e obter um relatório
que dê conta das 22 rotas não-destrutivas, uma a uma. Secundário e igualmente
medível: os 109 requests contra rotas inexistentes vão a zero.

### Etapa 2 — Conclusão

**Propriedade:** os checks conseguem chegar a uma conclusão sobre uma API com
input validado.

| Issue | Item | Por quê aqui |
|---|---|---|
| #21 | **`auth-required`** | O primeiro check que conclui onde os atuais não conseguem. Oráculo é status code, imune ao #30. Traz junto a identidade alternativa, que #25 depende |
| #20 | `Content-Type` awareness em `missing-headers` | Sinal antes de volume; corrige ruído do check existente |
| #28 | Body em rotas POST | Destrava `sqli`/`xss` nas rotas que hoje só parecem limpas |

**Critério de saída:** o scan da `task-api` produz pelo menos um veredito
positivo sustentado — "esta rota foi exercitada e está limpa" — em vez de
silêncio. E a razão de todo `Skipped` restante é uma limitação nomeada, não
"não sei".

### Etapa 3 — Família de configuração

**Propriedade:** o scanner cobre a classe de vulnerabilidade que mais aparece
em API de produção — configuração.

| Issue | Item |
|---|---|
| #14 | Probe set seguro na coleta (`Target.Probes`) |
| #22 | `cache-on-authenticated` |
| #23 | `cors-misconfigured` + `dangerous-http-methods` |

Ordem interna: #14 primeiro, e só porque tem três consumidores concretos
nesta mesma etapa (§4.2). Construído antes disso seria generalidade
especulativa.

**Critério de saída:** os três checks rodam sobre `Target.Probes` sem gastar
request próprio, e a coleta continua em 3 requests por endpoint.

### Etapa 4 — Continuidade

**Propriedade:** o scanner deixa de ser auditoria pontual e vira guarda.

| Issue | Item |
|---|---|
| #24 | `scanner diff` |
| #29 | Saída SARIF → gate de CI |

**Por que só agora, tendo sido o item 2 do plano original:** um diff sobre a
saída de hoje compara dois relatórios que não sabem o que não examinaram, e
reporta `-resolvido` para rota que só não foi olhada. A alavancagem do `diff`
é real; ela só existe sobre uma base honesta.

**Critério de saída:** duas execuções contra a `task-api` inalterada produzem
diff vazio, e desligar uma proteção no alvo produz exatamente uma linha `+`.

### Etapa 5 — Classes restantes

| Issue | Item |
|---|---|
| #25 | `idor` |
| #26 | `jwt-weak` |
| #27 | `verbose-errors` + `open-redirect` |

`idor` deixou de ser o degrau final: a identidade alternativa chega na Etapa 2,
com `auth-required`. Sobra o trabalho de verdade dele — descobrir, de forma
black-box e determinística, um recurso conhecidamente pertencente a um usuário.

**Fora de etapa:** extrair `pkg/` só quando existir um segundo consumidor real
— provavelmente quando o gate de CI amadurecer.

---

## 6.1 O que mudou em relação ao plano original

| Mudança | Razão |
|---|---|
| Dez issues que não existiam passam à frente de tudo | A auditoria (§3) e a medição (§3.3) acharam defeitos que o plano original não tinha como ver |
| `scanner diff` cai do 2º lugar para a Etapa 4 | Diff sobre relatório desonesto é verde falso |
| `auth-required` entra e vira o 1º check novo | Não existia no plano original; é o único que conclui contra API validada |
| O "bloco passivo" se desfaz | Três dos quatro não eram passivos (§2.1); `insecure-cookie-flags` sai por ser inócuo numa API JSON; `security-txt-missing` sai por ser higiene, não vulnerabilidade |
| `deps` vira passo de CI (#19) | Análise de fonte + resultado não comparável entre execuções (§2.3) |
| `rate-limit-bypass` sai do roadmap | Não determinístico e é teste de carga em miniatura (§2.3). Se voltar, em canal de saída próprio |
| `idor` deixa de ser o último | A identidade alternativa chega com `auth-required` |

---

## 7. O que fica de fora — e por quê

- **Teste de carga** (throughput, p99) — não comparável entre execuções, e um
  modo agressivo contradiz "gentil por design".
- **SAST / análise de fonte** — o scanner é black-box por decisão. Inclui
  `govulncheck`, que por isso vira passo de CI (§2.3).
- **Fuzzing profundo** — briga com gentileza e com comparabilidade.
- **Qualquer exploração que modifique estado** — o gate não-destrutivo é
  inegociável. Extração via `UNION SELECT` (só leitura) é o limite, e já é.
- **Heurística probabilística sem confirmação possível** — viola "só afirmo
  com prova".

A linha é sempre a mesma: dentro, a vulnerabilidade é propriedade **observável
de fora** e **provável sem machucar**; fora, exige estado interno, volume, ou
o código-fonte. O objetivo não é fazer tudo — é responder *uma* pergunta cada
vez melhor.
