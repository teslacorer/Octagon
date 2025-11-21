# API Defender (Java 21, CLI)

API Defender — консольный и Docker‑сканер безопасности для REST API, работающий по спецификациям OpenAPI 3 и набору проверок, основанных на OWASP API Security.  
Он проверяет контракт, обнаруживает скрытые эндпоинты, ищет типичные уязвимости (CORS, слабая авторизация, BOLA/IDOR, PII‑утечки и т.д.), считает риск по OWASP Risk Rating и формирует отчёты в форматах **HTML / PDF / JSON** с детальными трассами запросов.

Основные возможности:
- Контрактные проверки API по OpenAPI: статусы ответов, `Content-Type`, JSON‑схемы, обязательные заголовки.
- Автоматическое обнаружение неописанных эндпоинтов (undocumented / discovery).
- Набор прикладных сканеров:
  - CORS, Security Headers.
  - WeakAuth (слабая аутентификация).
  - BOLA/IDOR (доступ к чужим ресурсам по идентификатору).
  - BFLA, HPP, Pagination, Method Override.
  - RateLimit (отсутствие/слабые лимиты).
  - ExcessiveData (избыточные данные относительно OpenAPI).
  - PIILeak (утечка PII / бизнес‑критичных данных, например балансов).
  - MassAssignment, VerboseErrors и др.
- Автоматическая оценка риска по OWASP Risk Rating для каждой найденной проблемы.
- Опциональное AI‑обогащение выводов (модель `x-ai/grok-4.1-fast` через OpenRouter):
  - уточнение критичности (0–10),
  - русскоязычные рекомендации по устранению.

---

## Быстрый старт в Docker

### 1. Сборка образа

```bash
docker build -t apidefender:local -f docker/Dockerfile .
```

### 2. Базовый прогон (Windows PowerShell)

В каталоге, где лежат `openapi.json`, `token.jwt` и папка `out`:

```powershell
docker run --rm `
  -v "${PWD}/openapi.json:/app/specs/openapi.json" `
  -v "${PWD}/token.jwt:/secrets/token.jwt" `
  -v "${PWD}/out:/out" `
  apidefender:local scan `
  --openapi /app/specs/openapi.json `
  --token-file /secrets/token.jwt `
  --base-url https://api.example.com/ `
  --preset full `
  --timeout 5m `
  --report-html /out/report.html `
  --report-pdf /out/report.pdf `
  --report-json /out/report.json `
  --save-traces /out/traces `
  --log-file /out/scan.log `
  --log-level info
```

### 3. Базовый прогон (Linux/macOS, bash/zsh)

```bash
docker run --rm \
  -v "$PWD/openapi.json:/app/specs/openapi.json" \
  -v "$PWD/token.jwt:/secrets/token.jwt" \
  -v "$PWD/out:/out" \
  apidefender:local scan \
  --openapi /app/specs/openapi.json \
  --token-file /secrets/token.jwt \
  --base-url https://api.example.com/ \
  --preset full \
  --timeout 5m \
  --report-html /out/report.html \
  --report-pdf /out/report.pdf \
  --report-json /out/report.json \
  --save-traces /out/traces \
  --log-file /out/scan.log \
  --log-level info
```

### 4. Агрессивный прогон (больше проверок)

```powershell
docker run --rm `
  -v "${PWD}/openapi.json:/app/specs/openapi.json" `
  -v "${PWD}/token.jwt:/secrets/token.jwt" `
  -v "${PWD}/out:/out" `
  apidefender:local scan `
  --openapi /app/specs/openapi.json `
  --token-file /secrets/token.jwt `
  --base-url https://api.example.com/ `
  --preset aggressive `
  --timeout 5m `
  --public-path /,/status,/health `
  --allow-cors-wildcard-public `
  --report-html /out/report_aggr.html `
  --report-pdf /out/report_aggr.pdf `
  --report-json /out/report_aggr.json `
  --save-traces /out/traces_aggr `
  --log-file /out/scan_aggr.log `
  --log-level info `
  --safety-skip-delete `
  --exploit-depth med `
  --max-exploit-ops 40
```

> При каждом запуске CLI очищает старые файлы в каталоге `/out`, чтобы результаты не смешивались.

---

## Локальный запуск без Docker

Требования:
- Java 21,
- Maven 3.9+.

Сборка и запуск:

```bash
mvn -DskipTests -pl apidefender-cli -am package
java -jar apidefender-cli/target/apidefender-cli-*.jar scan \
  --openapi ./openapi.json \
  --token-file ./token.jwt \
  --base-url https://api.example.com/ \
  --preset full
```

---

## Параметры CLI

Все параметры задаются команде `scan`:

- `--openapi <path>` – путь к спецификации OpenAPI (JSON/YAML).  
  По умолчанию в Docker: `/app/specs/openapi.json`.
- `--base-url <url>` – базовый URL целевого API.  
  Если не указан, берётся `servers[0].url` из OpenAPI, иначе `http://localhost:8080`.
- `--token-file <path>` (обязательный) – файл с JWT‑токеном (подставляется в `Authorization: Bearer ...`).  
- `--preset <fast|full|aggressive>` – профиль интенсивности:  
  - `fast` – быстрый чек, минимальный набор запросов;
  - `full` – баланс скорости и глубины;
  - `aggressive` – максимум проверок и эвристик.
- `--timeout <dur>` – общий таймаут сканирования (например, `30s`, `5m`, `1h`). По умолчанию: `5m`.
- `--concurrency <N>` – число параллельных потоков:  
  - если не указано, выбирается автоматически (в aggressive сейчас 2 потока для снижения нагрузки).
- `--report-html <path>` – путь к HTML‑отчёту (по умолчанию `/out/report.html`).
- `--report-pdf <path>` – путь к PDF‑отчёту (по умолчанию `/out/report.pdf`).
- `--report-json <path>` – путь к JSON‑отчёту (по умолчанию `/out/report.json`).
- `--save-traces <dir>` – каталог для raw‑трейсов запросов/ответов (по умолчанию `/out/traces`).
- `--log-file <path>` – JSONL‑лог сканирования (по умолчанию `/out/scan.log`).
- `--log-level <info|debug>` – уровень подробности логов.
- `--discover-undocumented` – включить сканеры discovery (по умолчанию `true`).
- `--strict-contract` – строгая проверка контракта (mismatch по статусам, заголовкам, схемам).
- `--public-path <list>` – список явно публичных путей (через запятую), влияет на некоторые проверки CORS/WeakAuth.
- `--allow-cors-wildcard-public` – разрешить `Access-Control-Allow-Origin: *` только на публичных путях (по умолчанию `true`).
- `--exploit-depth <low|med|high>` – глубина агрессивных проверок (по умолчанию зависит от пресета).
- `--max-exploit-ops <N>` – общий лимит «агрессивных» операций (по умолчанию `40`).
- `--safety-skip-delete` – запрет выполнять реальные `DELETE`‑запросы в агрессивных проверках.
- `--debug` – включить debug‑лог (дополнительные детали по каждому сканеру).
- `--mask-secrets` – маскировать секреты (JWT/токены/PII) в логах и отчётах (по умолчанию `true`).
- `--telemetry-endpoint <url>` / `--telemetry-opt-in` – опциональная отправка анонимной статистики (кол‑во запросов, длительность сканеров) на внешний endpoint.

### Параметры AI

- `--ai-enabled` – включить AI‑обогащение находок через OpenRouter.
- `--ai-key-file <path>` – путь к файлу с API‑ключом OpenRouter (по умолчанию `./api_key.txt`).  
  В Docker чаще монтируется как `/secrets/api_key.txt`.
- `--ai-model <id>` – идентификатор модели OpenRouter.  
  По умолчанию: `x-ai/grok-4.1-fast`.
- `--ai-timeout <dur>` – таймаут для AI‑запросов (например, `20s`). По умолчанию: `20s`.

AI получает список найденных уязвимостей (без секретов), возвращает для каждой:
- числовую оценку критичности `severity_0_10`,
- русскоязычную рекомендацию `recommendation_ru`.

Результат пишется в поля `aiSeverity`, `aiRecommendation`, `aiModel` в JSON‑, HTML‑ и PDF‑отчётах.

---

## Типы проверок (сканеры)

Каждый сканер реализует интерфейс `SPI` и получает общий контекст: OpenAPI, HttpClient, логгер, модель отчёта, список эндпоинтов, параметры пресета и лимиты.

Основные сканеры:

- **SecurityHeaders** (`SecurityHeadersScanner`)  
  Проверяет наличие ключевых заголовков безопасности на публичном корне `/`:
  - `X-Content-Type-Options`,
  - `X-Frame-Options`,
  - `Strict-Transport-Security`,
  - и другие базовые заголовки.

- **CORS** (`CorsHeadersScanner`)  
  Анализирует настройки `Access-Control-Allow-Origin` и связанные заголовки.  
  Отдельно учитывает `public-path` и флаг `allow-cors-wildcard-public`.

- **WeakAuth** (`WeakAuthScanner`)  
  Ищет случаи, когда:
  - доступ к ресурсу возможен без `Authorization`,
  - или с «явно неверным» токеном (`Bearer invalid...`) сервер всё равно отвечает 2xx.

- **BOLA / IDOR** (`BolaIdorScanner`, `ChainedIdorScanner`)  
  Пробует подмену идентификаторов в путях и параметрах (например `accountId`, `paymentId`, `externalAccountID`) в пределах одного токена, чтобы выявить доступ к чужим ресурсам.

- **BFLA** (`BflaScanner`)  
  Эвристика проверки бизнес‑логики доступа: подозрительные комбинации методов/ресурсов (например, возможность отмены/подтверждения операций без ожидаемых шагов).

- **HPP** (`HppScanner`) – HTTP Parameter Pollution  
  Проверяет реакции сервера на дублирующиеся параметры (`id=1&id=2`, и т.п.).

- **Pagination** (`PaginationScanner`)  
  Проверяет корректность пагинации: ограничения на page/size, реакции на большие значения, консистентность ответов.

- **MethodOverride** (`MethodOverrideScanner`)  
  Ищет наличие `X-HTTP-Method-Override` и схожих механизмов, которые могут позволить обойти ограничения по методам.

- **RateLimit** (`RateLimitScanner`)  
  Для небольшого набора GET‑эндпоинтов делает серию запросов (`rateBurst`, в aggressive сейчас ~15) и анализирует:
  - присутствие 429‑ответов,
  - наличие `X-RateLimit-*` / `Retry-After`.

- **ExcessiveData** (`ExcessiveDataScanner`)  
  Сопоставляет JSON‑ответы с OpenAPI‑схемой и ищет:
  - поля, которых нет в описанной схеме (`additionalProperties = false`),
  - потенциальную PII в теле ответа (email/phone/card/ключевые слова).

- **PIILeak** (`PiiLeakScanner`)  
  Делает GET‑запросы к описанным в OpenAPI путям и ищет в 2xx‑ответах:
  - email, телефоны, номера карт (с luhn‑проверкой),
  - слова вроде `passport`, `inn`, `снилс`, и т.п.,
  - баланс/баллы/лимиты и др. бизнес‑критичные данные (`availableBalance`, `reward`, `points`, `баланс`, `баллы`, …),
  - строки, похожие на имена (латиница и кириллица),
  - «человекоподобный» текст достаточной длины.  
  При нахождении формирует категорию `PIILeak`.

- **MassAssignment** (`MassAssignmentScanner`)  
  Пытается добавить в запросы поля, отсутствующие в схеме OpenAPI, чтобы проверить, принимаются ли лишние данные.

- **VerboseErrors** (`VerboseErrorsScanner`)  
  Посылает «ломаные» запросы и ищет в 5xx‑ответах признаки подробных ошибок:
  - `Exception:`, `Stack trace`, стеки и т.п.

- **Undocumented** (`UndocumentedScanner`, `GuidedDiscoveryScanner`)  
  - Проверяет типовые служебные пути:
    - `/health`, `/status`, `/metrics`, `/actuator/*`, `/admin/*`, `/internal/*`, `/swagger*`, `/v3/api-docs`, `/openapi.json`, `/apidocs`, `/docs/index.html`, `/webjars/swagger-ui/index.html`, и др.
  - Генерирует кандидатов на основе сегментов из OpenAPI: `/segment/debug`, `/segment/internal`, `/segment/metrics`, `/segment/health`, `/segment/status`.
  - Если эндпоинт отвечает `2xx/401/403` и не описан в OpenAPI — создаётся `Undocumented`‑уязвимость.

> Отдельного Injection‑сканера сейчас нет — он отключён, так как в текущем контексте не давал практических результатов.

Помимо сканеров, для каждой операции выполняется **контрактная проверка**:
- соответствие статус‑кодов описанным в `responses`,
- соответствие `Content-Type`,
- валидация JSON‑ответа по схеме, включая `oneOf/anyOf/allOf`,
- наличие обязательных заголовков ответа.

---

## Структура проекта

- `apidefender-core/` – ядро:
  - `core/Config.java` – конфигурация сканирования (пресеты, таймауты, пути отчётов).
  - `core/http/HttpClient.java` – обёртка над OkHttp с токеном, корреляционными заголовками и троттлингом (задержка между запросами в зависимости от пресета).
  - `core/http/Masking.java` – маскирование секретов в логах/трейсах.
  - `core/openapi/OpenApiLoader.java` – загрузка и парсинг OpenAPI, выбор базового URL.
  - `core/report/ReportModel.java` – модель отчёта (meta, contract mismatches, security issues, telemetry).
  - `core/report/ReportWriter.java` – генерация JSON, HTML, PDF.
  - `core/report/HtmlTemplates.java` – шаблон HTML‑отчёта.
  - `core/risk/RiskAssessor.java` – эвристический OWASP Risk Rating (likelihood, impact, score, rating).
  - `core/log/JsonlLogger.java` – структурированный JSONL‑логгер (stdout + файл).

- `apidefender-scanners/` – набор сканеров и SPI:
  - `scanners/SPI.java` – интерфейс `SPI` и `ScanContext` (общий контекст сканирования, генерация URL с подстановкой path‑параметров).
  - `scanners/simple/*` – простые сканеры заголовков (CORS, SecurityHeaders).
  - `scanners/owasp/*` – доменные и OWASP‑ориентированные сканеры (WeakAuth, BOLA/IDOR, PIILeak, ExcessiveData, RateLimit, MassAssignment, VerboseErrors, BFLA, HPP, Pagination, MethodOverride, Undocumented/GuidedDiscovery и др.).

- `apidefender-reporting/` – отчётность:
  - `core/report/ReportWriter.java` – запись JSON/HTML/PDF.
  - `core/report/HtmlTemplates.java` – HTML‑разметка отчёта, включающая сводку по severity, risk, телеметрию, slow endpoints и детальные таблицы.

- `apidefender-cli/` – CLI:
  - `cli/Main.java` – точка входа (`apidefender`).
  - `cli/commands/ScanCommand.java` – команда `scan`, парсинг CLI‑флагов, запуск сканеров, агрегация результатов, вызов AI.
  - `cli/ai/AiAdvisor.java` – интеграция с OpenRouter, группировка уязвимостей по чанкам, парсинг JSON‑ответа AI.

- `docker/Dockerfile` – многоступенчатая сборка (Maven + JRE), оптимизирована под кэш и PDF‑рендеринг (fonts‑dejavu).
- `openapi.json` – пример спецификации API.
- `out/` – каталог для отчётов, логов и трейсов (монтируется в Docker).

Проект построен как Maven‑multi‑module:
- корневой `pom.xml` – общие зависимости и BOM (Jackson и др.),
- модули: `apidefender-core`, `apidefender-scanners`, `apidefender-reporting`, `apidefender-cli`.

---

## Токены и ключи

- **JWT‑токен**:
  - кладётся в файл, путь передаётся через `--token-file` (например, `./token.jwt`),
  - в Docker монтируется как `/secrets/token.jwt`,
  - автоматически добавляется в каждый запрос в виде `Authorization: Bearer <token>`.

- **API‑ключ для AI (OpenRouter)**:
  - по умолчанию читается из `./api_key.txt` (или любого пути, указанного в `--ai-key-file`),
  - в Docker обычно монтируется как `/secrets/api_key.txt`,
  - используется только при `--ai-enabled`.

> Содержимое ключей и JWT нигде не логируется в открытом виде (маскируется перед записью в отчёты и логи, если включён `--mask-secrets`).

---

## Отчёты и трассы

После завершения сканирования в каталоге `out/` появляются:

- `report.json` – машиночитаемый отчёт:
  - `meta` – времена начала/окончания, preset, target, версия OpenAPI, количество эндпоинтов.
  - `contract` – список несоответствий контракту (status, headers, schema, undocumented).
  - `security` – массив найденных уязвимостей (`category`, `severity`, `endpoint`, `method`, `description`, `evidence`, `impact`, `recommendation`, `traceRef`, `aiSeverity`, `aiRecommendation`, `aiModel`).
  - `telemetry` – суммарная статистика сканирования (кол‑во запросов, средняя задержка, счётчики по категориям, время работы сканеров).
- `report.html` – удобный человекочитаемый отчёт с таблицами и цветовой подсветкой по severity/risk, разворачиваемыми деталями и встроенными трейcами.
- `report.pdf` – PDF‑версия HTML‑отчёта.
- `scan.log` – JSONL‑лог (`ts`, `level`, `msg`), пригодный для последующего анализа/агрегации.
- `traces/` – сырые трейсы:
  - файлы вида `METHOD_https_host_path_code_timestamp.json`,
  - содержат URL, метод, заголовки запроса/ответа и тело (с маской секретов).

В HTML‑отчёте для каждой уязвимости есть ссылка **Details**, где можно увидеть конкретный запрос/ответ и имя файла трейса.

---

## Пресеты и практические рекомендации

- `fast` – быстрый «smoke test»:
  - минимальное число запросов,
  - небольшое число кандидатов discovery,
  - разумные лимиты IDOR/RateLimit проверок.

- `full` – основной режим:
  - покрытие всех операций из OpenAPI,
  - полный набор сканеров,
  - умеренная нагрузка.

- `aggressive` – максимальная глубина:
  - больше попыток BOLA/IDOR, MassAssignment и пр.,
  - расширенный discovery (`UndocumentedScanner` + `GuidedDiscoveryScanner`),
  - больше тестов RateLimit/PII.

Безопасность и аккуратность:
- в aggressive по умолчанию включены:
  - троттлинг запросов на уровне HttpClient,
  - пониженный `concurrency`, чтобы не уткнуться в Rate Limit, а реальные ответы оставить доступными для анализа;
  - опция `--safety-skip-delete` (DELETE‑запросы в «опасных» сценариях не исполняются).
- опция `--mask-secrets` защищает от случайной утечки токенов и чувствительных данных в логах и отчётах.

---

## Ограничения и дальнейшее развитие

Текущая версия ориентирована на:
- один JWT‑токен (одна роль/один пользователь),
- HTTP‑интерфейсы, описанные в OpenAPI 3.0/3.1,
- OpenRouter как AI‑провайдера.

Потенциальные направления развития:
- поддержка сценариев с несколькими ролями/пользователями для BOLA/BFLA,
- расширение генерации запросов по OpenAPI (body/query‑варианты, boundary‑cases),
- интеграция с другими AI‑провайдерами,
- дополнительные сканеры под конкретные домены (банковские API, FAPI/PSD2 и т.п.).

Тем не менее уже сейчас API Defender даёт удобный и довольно глубокий обзор безопасности API, опираясь на контракт, реальные ответы сервера и AI‑обогащение отчёта.
