# PROMPT_Codex.md (EN — main step-by-step prompt for the code agent)

## Mission
Build a **Dockerized Java 21 CLI tool** that automatically audits a bank’s API for **contract compliance** (OpenAPI) and **security issues** (OWASP API Security Top-10), producing **HTML, PDF, and JSON** reports within **≤ 5 minutes** for ~60–70 endpoints. Primary user is a **security engineer**. Project UI/docs are **Russian**; this prompt is **English**.

### Key Sources
- Provided OpenAPI file: `specs/openapi.json` (already available).
- Target bank: **VBank**. Base portal: `https://vbank.open.bankingapi.ru/` (derive actual base path from the spec).
- Auth: **JWT Bearer** using a **client token** supplied via file (path flag).
- No roles. All endpoints may be exercised, including modifying operations (no confirmations).
- No proxy / GOST gateway. Local run in Docker.

## High-Level Requirements
- **Language/Runtime**: Java **21**.
- **Packaging/Run**: Single Docker image (`amd64` & `arm64`), CLI entrypoint inside the container.
- **Time budget**: Default scan finishes ≤ **5 minutes** on ~60–70 endpoints.
- **Presets**: `fast`, `full` (default), `aggressive`. Respect time budget (favor coverage over depth).
- **Parallelism**: Sensible default (auto), tunable via flag.
- **Reports**: HTML + PDF + JSON. Severity model: **OWASP Risk Rating**.
- **Logs**: **JSONL**; detailed by default. `--debug` prints full request/response (mask JWT only).
- **Telemetry (anonymous)**: duration, endpoints count, checks count, average latency, % contract mismatches, vuln counts by severity, etc.
- **Artifacts**: Save **raw requests/responses** and step traces (mask JWT). Keep reproducibility first.
- **Localization**: CLI strings, README, user-facing docs/report are **Russian**.

## Scope of Checks

### Contract (strict)
- Validate request/response against OpenAPI: types, required, formats, additional/unknown fields.
- Diff **observed behavior vs spec**.
- Discover **undocumented** paths/methods (probing + heuristics for common admin/health/debug routes).

### OWASP API Security (prioritized)
1) **BOLA / IDOR**: attempt cross-access using harvested identifiers across sessions/tokens (we only have a single client token; emulate identity confusion via crafted IDs and state).
2) **Injection**: SQL/NoSQL/LDAP/Path/Command payloads into query/body/headers; timing/error heuristics.
3) **Weak Authentication**: missing/lenient auth on sensitive routes; token handling mistakes; token expiry handling; auth bypass attempts.
4) **Excessive Data Exposure**: detect fields not specified in the schema; leak of PII-like patterns.
Plus:
- **CORS**, **security headers**, **rate limit** signals, **mass assignment**, **verbose error details** (stack traces).

> Active attacks are permitted on the test API. There are **no rate limits** and **no role separation**.

## CLI Contract (Russian strings)
Binary name (inside container): `apidefender`.

Required/optional flags (kebab-case; RU help texts):
- `--openapi <path>`: путь к OpenAPI (JSON/YAML). Default: `/app/specs/openapi.json`
- `--base-url <url>`: базовый URL сервиса (если не задан — брать из сервера/servers спеки)
- `--token-file <path>`: путь к файлу с JWT (одна строка). **Обязательно**
- `--preset <fast|full|aggressive>`: профиль сканирования. Default: `full`
- `--timeout <dur>`: общий таймаут, например `5m`. Default: `5m`
- `--concurrency <N>`: степень параллелизма. Default: авто
- `--discover-undocumented`: включить поиск неописанных эндпоинтов. Default: on
- `--strict-contract`: строгая проверка контракта. Default: on
- `--report-html <path>`: HTML отчёт. Default: `/out/report.html`
- `--report-pdf <path>`: PDF отчёт. Default: `/out/report.pdf`
- `--report-json <path>`: JSON отчёт (единый файл). Default: `/out/report.json`
- `--save-traces <dir>`: каталог для raw запросов/ответов. Default: `/out/traces`
- `--log-level <info|debug>`: уровень логирования. Default: `info`
- `--mask-secrets`: маскирование секретов (JWT). Default: on

Exit codes: `0` success; `1` runtime error; `2` invalid input/spec; `3` timeout.

## Architecture & Modules (generate code accordingly)
Use **Maven** multi-module (you may choose Gradle if you prefer; Maven is recommended).

```
apidefender/
 ├─ apidefender-cli/           # picocli main(), flags, presets, progress output (RU)
 ├─ apidefender-core/          # runner, HTTP client, auth, parallel scheduler, storage, telemetry
 ├─ apidefender-contract/      # OpenAPI parsing & validation, diff, undocumented discovery
 ├─ apidefender-scanners/      # OWASP checks as plugins (SPI)
 │   ├─ scanner-bola/
 │   ├─ scanner-idor/
 │   ├─ scanner-injection/
 │   ├─ scanner-auth/
 │   └─ scanner-excess-data/
 ├─ apidefender-report/        # JSON model, HTML templating, PDF rendering, OWASP Risk Rating
 ├─ apidefender-logging/       # JSONL logging utilities, masking, request/response dump
 └─ docker/                    # Dockerfile, entrypoint, examples
```

Key libraries (preferred):
- HTTP: `java.net.http` or `OkHttp`.
- OpenAPI: `openapi4j` (validation), `swagger-parser` (parsing), `openapi-diff`.
- JSON: `Jackson`.
- CLI: `picocli`.
- Reports: template engine (`Pebble` or `Freemarker`) + `openhtmltopdf` for PDF.
- Tests: JUnit 5.
- Style: Spotless/Checkstyle.
- Logging: SLF4J + Logback (JSON encoder) or custom JSONL appender.

Plugin system: Java `ServiceLoader` (SPI). Each scanner exposes:
- metadata (name, version, category),
- `prepare(spec, endpoints, authCtx)`,
- `scan(targets, budget, logger)` returning findings + traces.

## Performance Rules
- Use parallelism for endpoints/methods. Avoid storming: bounded pools; collapse duplicates.
- Cache schema validators; reuse HTTP connections.
- Presets:
  - `fast`: contract + light security probes.
  - `full` (default): all required checks with sample payload set.
  - `aggressive`: expanded payloads, more fuzz boundaries (still respect global timeout).
- Enforce global `--timeout`. If exceeded, finalize reports with partial data.

## Reporting (JSON/HTML/PDF)
- JSON schema provided in `REPORT_SCHEMA.json` — **adhere to it**.
- Each finding: `id`, `category` (owasp key), `severity` (OWASP Risk Rating), `endpoint`, `method`, `description`, `evidence` (request/response excerpts, diffs), `impact`, `recommendation`, `traceRef` to raw artifacts.
- Include contract section (mismatches, undocumented endpoints).
- Include telemetry section (anonymous metrics).

## Security & Redaction
- Never print the raw JWT; mask as `***`.
- Save raw requests/responses to `/out/traces` with JWT masked.
- Do not mask other data (per requirements).

## Docker
- Base: `eclipse-temurin:21-jre` (slim).
- Multi-arch support (amd64/arm64). Provide build instructions in README.
- Entry: `apidefender scan ...` with flags.
- Mounts:
  - `-v $PWD/out:/out`
  - `-v $PWD/openapi.json:/app/specs/openapi.json`
  - `-v $PWD/token.jwt:/secrets/token.jwt`

## Acceptance Criteria (must pass)
1. Runs via Docker; finishes `--preset full` within **≤ 5 minutes** on provided spec; produces **HTML/PDF/JSON**.
2. Performs strict OpenAPI validation and reports **undocumented** endpoints/methods (if discovered).
3. Implements prioritized OWASP checks: **BOLA, IDOR, Injection, Weak Auth, Excessive Data**; plus CORS, security headers, rate-limit signals, mass assignment, verbose errors.
4. Logs in **JSONL**, saves raw traces (with JWT masked).
5. Uses **OWASP Risk Rating** to label severities.
6. Russian-language CLI help and user docs.

## Step-by-Step Tasks (generate in order)
1. Scaffold Maven multi-module project & package names; configure Java 21, dependencies, Spotless/Checkstyle, JUnit 5.
2. Implement core runner with time budget, concurrency controls, HTTP client, token loading from file, servers/baseURL resolution from OpenAPI.
3. Implement OpenAPI loader & validator (JSON/YAML), strict schema validation (request/response), and **behavior vs spec diff**.
4. Implement **undocumented discovery** routine (probing common paths/methods; safe heuristics).
5. Implement **scanner SPI** and the five prioritized scanners (+ auxiliary checks) with minimal but effective payload sets.
6. Implement **reporting**: JSON per `REPORT_SCHEMA.json`, HTML templates (RU), and PDF via HTML rendering.
7. Implement **logging JSONL** + masking + raw trace storage.
8. Implement **CLI (picocli)** with flags, RU help text, and **presets**.
9. Implement **Docker** (multi-arch build notes). Ensure entrypoint & examples.
10. Add **tests**: unit for validators, functional smoke on a subset of endpoints (mock if needed), and time-budget test.
11. Polish: README (RU), examples, sample commands, troubleshooting.

Produce clean, production-grade code with comments where non-obvious. Keep strings user-facing in Russian.
