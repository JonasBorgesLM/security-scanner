# Rodando o scanner como gate de CI

O scanner produz dois artefatos que um pipeline consome: um **SARIF**, que o
GitHub Code Scanning lê nativamente, e um **exit code** do `scanner diff`,
que decide se o build passa.

---

## A política de exit code

| Comando | 0 | 1 | 2 |
|---|---|---|---|
| `scan` / `attack` / `report` | sucesso | falhou | — |
| `diff` | nada piorou | a comparação quebrou | **a execução nova está pior** |

O 2 é separado do 1 de propósito. Um passo de CI que não distingue os dois
**trata um scanner quebrado como um relatório limpo** — que é a mesma
confusão que a Etapa 1 gastou-se eliminando, reencenada no nível do pipeline.

O que conta como "pior" são duas coisas, e a segunda é a que um diff comum
não enxerga:

1. Um finding novo com severidade igual ou acima de `--fail-on` (padrão: `high`).
2. **Cobertura que existia e não existe mais.** Uma execução que examina
   menos que a anterior regrediu mesmo com a lista de findings mais curta —
   especialmente então, porque é assim que quebrar o scanner se parece visto
   de fora.

---

## Workflow de exemplo

```yaml
name: Security scan

on:
  schedule: [{cron: "0 6 * * 1"}]
  workflow_dispatch:

permissions:
  contents: read
  security-events: write   # necessário para publicar o SARIF

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with: {go-version-file: go.mod}

      - name: Build the scanner
        run: go build -o scanner ./cmd/scanner

      # O alvo precisa estar no ar e dentro de scope.allowed_hosts.
      - name: Start the target
        run: docker compose up -d --wait

      - name: Scan
        env:
          LAB_PASSWORD: ${{ secrets.LAB_PASSWORD }}
        run: |
          ./scanner scan   --spec docs/openapi.yaml --config ci.yaml --out findings.json
          ./scanner attack --in findings.json --config ci.yaml --out confirmed.json
          ./scanner report --in confirmed.json --out report.html --sarif report.sarif

      - name: Publish to Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with: {sarif_file: report.sarif}

      # A baseline vem de uma execução anterior — um artefato, um commit, o
      # que for. Sem ela o gate não tem contra o que comparar, e o passo é
      # pulado em vez de passar por engano.
      - name: Compare against the baseline
        if: hashFiles('baseline/confirmed.json') != ''
        run: ./scanner diff baseline/confirmed.json confirmed.json
```

---

## O que o SARIF carrega, e o que ele não pode carregar

**Localização.** Estes achados estão em rotas de um alvo em execução, não em
linhas de arquivo. O `artifactLocation.uri` recebe a **URL do request que
produziu o finding**, que é verdade. Apontar para um arquivo-fonte que o
scanner nunca leu, só para a anotação cair numa linha, não seria — e por isso
as anotações aparecem na aba Security sem se ancorar em código.

**Severidade.** Duas escalas: `level` (`error`/`warning`/`note`) e
`security-severity` (0–10), que é o número pelo qual o GitHub ordena e
filtra. Omitir a segunda joga todo finding no mesmo balde.

**Cobertura.** O Code Scanning não tem conceito de "não consegui examinar",
então um writer de SARIF ingênuo **descarta o bloco `coverage`** — e este
passaria a ser o único formato onde uma lista vazia não se distingue de um
alvo limpo. As lacunas vão para
`invocations[].toolExecutionNotifications`, que é o lugar do próprio SARIF
para a ferramenta ter algo a dizer sobre a execução em vez de sobre o código.

Elas não viram anotações no código — o GitHub não as exibe ao lado dos
resultados. Ficam no arquivo, para quem for lê-lo. É menos do que se queria,
e é o máximo que o formato permite sem inventar localização.
