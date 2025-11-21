# API Defender (Java 21, CLI)

API Defender — консольный и Docker‑сканер безопасности для REST API, работающий по спецификациям OpenAPI 3 и использующий специализированные сканеры для выявления уязвимостей согласно OWASP API Security и лучшим практикам.  
Инструмент проверяет контракт API, обнаруживает скрытые эндпоинты, ищет типичные уязвимости (слабая авторизация, BOLA/IDOR, утечки PII, инъекции, избыточное раскрытие данных и т.д.), оценивает риск по OWASP Risk Rating и формирует отчёты в форматах **HTML / PDF / JSON** с детальными трассами запросов.

### Основные возможности:

- **Контрактные проверки** API по OpenAPI: статусы ответов, `Content-Type`, JSON‑схемы, обязательные заголовки.
- **Обнаружение скрытых эндпоинтов** (undocumented / discovery).
- **Специализированные GOST-сканеры** для выявления уязвимостей:
  - Проверки аутентификации и авторизации (слабые токены, отсутствие проверок).
  - BOLA/IDOR (доступ к чужим ресурсам по идентификатору).
  - Инъекции (SQL, path traversal и пр.).
  - Утечки PII и конфиденциальных данных.
  - Избыточное раскрытие информации в ответах.
  - Специализированные проверки для платежных и финансовых операций.
- **Автоматическая оценка риска** по OWASP Risk Rating для каждой найденной проблемы.
- **Опциональное AI‑обогащение** выводов (модель `x-ai/grok-4.1-fast` через OpenRouter):
  - уточнение критичности (0–10),
  - русскоязычные рекомендации по устранению.

---

## Быстрый старт в Docker

### 1. Сборка образа

```bash
docker build -t apidefender:local -f docker/Dockerfile .
```

### 2. Базовый прогон (Windows PowerShell)

В каталоге, где лежат `openapi.json`, `token.jwt`, `api_key.txt` и папка `out`:

```powershell
docker run --rm `
  -v "${PWD}:/app/specs" `
  -v "${PWD}/token.jwt:/secrets/token.jwt" `
  -v "${PWD}/api_key.txt:/secrets/api_key.txt" `
  -v "${PWD}/out:/out" `
  apidefender:local scan `
  --openapi /app/specs/openapi.json `
  --token-file /secrets/token.jwt `
  --preset full `
  --timeout 5m `
  --report-html /out/report.html `
  --report-pdf /out/report.pdf `
  --report-json /out/report.json `
  --save-traces /out/traces `
  --log-file /out/scan.log `
  --log-level info `
  --ai-enabled `
  --ai-key-file /secrets/api_key.txt `
  --ai-timeout 80s
```

### 3. Базовый прогон (Linux/macOS, bash/zsh)

```bash
docker run --rm \
  -v "$PWD:/app/specs" \
  -v "$PWD/token.jwt:/secrets/token.jwt" \
  -v "$PWD/api_key.txt:/secrets/api_key.txt" \
  -v "$PWD/out:/out" \
  apidefender:local scan \
  --openapi /app/specs/openapi.json \
  --token-file /secrets/token.jwt \
  --preset full \
  --timeout 5m \
  --report-html /out/report.html \
  --report-pdf /out/report.pdf \
  --report-json /out/report.json \
  --save-traces /out/traces \
  --log-file /out/scan.log \
  --log-level info \
  --ai-enabled \
  --ai-key-file /secrets/api_key.txt \
  --ai-timeout 80s
```

### 4. Агрессивный прогон (больше проверок)

```powershell
docker run --rm `
  -v "${PWD}:/app/specs" `
  -v "${PWD}/token.jwt:/secrets/token.jwt" `
  -v "${PWD}/api_key.txt:/secrets/api_key.txt" `
  -v "${PWD}/out:/out" `
  apidefender:local scan `
  --openapi /app/specs/openapi.json `
  --token-file /secrets/token.jwt `
  --preset aggressive `
  --timeout 5m `
  --report-html /out/report_aggr.html `
  --report-pdf /out/report_aggr.pdf `
  --report-json /out/report_aggr.json `
  --save-traces /out/traces_aggr `
  --log-file /out/scan_aggr.log `
  --log-level info `
  --ai-enabled `
  --ai-key-file /secrets/api_key.txt `
  --ai-timeout 80s `
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
  --preset full \
  --ai-enabled \
  --ai-key-file ./api_key.txt \
  --ai-timeout 80s
```

---

## Параметры CLI

Все параметры задаются команде `scan`:

- `--openapi <path>` – путь к спецификации OpenAPI (JSON/YAML).  
  По умолчанию в Docker: `/app/specs/openapi.json`.
- `--token-file <path>` (обязательный) – файл с JWT‑токеном (подставляется в `Authorization: Bearer ...`).  
- `--preset <fast|full|aggressive>` – профиль интенсивности:  
  - `fast` – быстрый чек, минимальный набор запросов;
  - `full` – баланс скорости и глубины;
  - `aggressive` – максимум проверок и эвристик.
- `--timeout <dur>` – общий таймаут сканирования (например, `30s`, `5m`, `1h`). По умолчанию: `5m`.
- `--concurrency <N>` – число параллельных потоков (если не указано, выбирается автоматически).
- `--report-html <path>` – путь к HTML‑отчёту (по умолчанию `/out/report.html`).
- `--report-pdf <path>` – путь к PDF‑отчёту (по умолчанию `/out/report.pdf`).
- `--report-json <path>` – путь к JSON‑отчёту (по умолчанию `/out/report.json`).
- `--save-traces <dir>` – каталог для raw‑трейсов запросов/ответов (по умолчанию `/out/traces`).
- `--log-file <path>` – JSONL‑лог сканирования (по умолчанию `/out/scan.log`).
- `--log-level <info|debug>` – уровень подробности логов.
- `--strict-contract` – строгая проверка контракта (mismatch по статусам, заголовкам, схемам).
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

## Типы проверок (сканеры GOST)

API Defender использует набор специализированных GOST-сканеров, адаптированных для проверки безопасности REST API в соответствии с требованиями и лучшими практиками.

Каждый сканер реализует интерфейс `SPI` и получает общий контекст: OpenAPI, HttpClient, логгер, модель отчёта, список эндпоинтов, параметры пресета и лимиты.

### Активные GOST-сканеры:

- **GostWeakAuthScanner** (`GostWeakAuthScanner`)  
  Проверяет наличие уязвимостей в аутентификации и авторизации:
  - доступ к защищённым ресурсам без `Authorization`,
  - принятие заведомо невалидных JWT-токенов (например `Bearer invalid...`),
  - отсутствие обязательной проверки прав доступа на чувствительных эндпоинтах.

- **GostBolaScanner** (`GostBolaScanner`)  
  Выявляет уязвимости BOLA/IDOR (доступ к ресурсам других пользователей):
  - пробует подмену идентификаторов (например `publicId`, `accountId`, `paymentId`),
  - проверяет возможность изменения/чтения чувствительных данных (credentials, CVV, tokens, балансы),
  - учитывает банковские сценарии и эвристики для выявления несанкционированного доступа.

- **GostExcessiveDataScanner** (`GostExcessiveDataScanner`)  
  Выявляет избыточное раскрытие данных:
  - анализирует JSON‑ответы и сравнивает с OpenAPI-схемой,
  - ищет поля, отсутствующие в контракте,
  - обнаруживает утечку чувствительной информации (пароли, токены, секреты, PII).

- **GostTracePiiScanner** (`GostTracePiiScanner`)  
  Ищет утечки личной идентифицирующей информации в ответах API:
  - email, телефоны, номера карт (с проверкой по Luhn),
  - паспортные данные, ИНН, СНИЛС,
  - баланс, баллы, лимиты и другие бизнес-критичные данные,
  - личные имена и персональные данные,
  - неотмаскированные или чрезмерно детальные ошибки.

- **GostInjectionScanner** (`GostInjectionScanner`)  
  Проверяет на уязвимости инъекций:
  - SQL injection,
  - path traversal (`../../etc/passwd`),
  - операционная система команды,
  - логический анализ для выявления blind-инъекций.

- **GostHackathonScanner** (`GostHackathonScanner`)  
  Специализированный сканер для выявления уязвимостей, характерных для API-приложений на базе банковских и финтех-платформ:
  - анализирует эндпоинты по чувствительности контента (сумма, пароль, токен, учетные данные),
  - применяет эвристики для приоритизации проверок,
  - ищет комбинации критичных операций.

- **GostContractScanner** (`GostContractScanner`)  
  Проверяет соответствие между фактическим поведением API и его OpenAPI-контрактом:
  - статус-коды ответов,
  - типы содержимого (`Content-Type`),
  - валидация JSON‑ответов по схеме (включая `oneOf/anyOf/allOf`),
  - обязательные и опциональные заголовки ответов.

- **GostIdDiscoveryScanner** (`GostIdDiscoveryScanner`)  
  Обнаруживает неописанные (скрытые) эндпоинты API:
  - проверяет типовые служебные пути (`/health`, `/status`, `/metrics`, `/actuator/*`, `/admin/*`, `/internal/*`, `/swagger*`),
  - генерирует кандидатов на основе сегментов из OpenAPI,
  - выявляет эндпоинты, которые отвечают 2xx/401/403 но не описаны в контракте.

- **GostPaymentsScanner** (`GostPaymentsScanner`)  
  Узкоспециализированный сканер для проверки безопасности платёжных и финансовых операций:
  - анализирует логику платежей и подтверждения операций,
  - проверяет возможность манипуляции сумм и параметров платежа,
  - ищет обходы процессов авторизации в платежных потоках.

Помимо сканеров, для каждой операции выполняется **контрактная проверка** (через `GostContractScanner`):
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

- `apidefender-scanners/` – набор GOST-сканеров и SPI:
  - `scanners/SPI.java` – интерфейс `SPI` и `ScanContext` (общий контекст сканирования, генерация URL с подстановкой path‑параметров).
  - `scanners/gost/*` – GOST-сканеры: `GostWeakAuthScanner`, `GostBolaScanner`, `GostExcessiveDataScanner`, `GostTracePiiScanner`, `GostInjectionScanner`, `GostHackathonScanner`, `GostContractScanner`, `GostIdDiscoveryScanner`, `GostPaymentsScanner` и др.

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
  - базовый набор GOST-сканеров.

- `full` – основной режим (рекомендуется):
  - покрытие всех операций из OpenAPI,
  - полный набор GOST-сканеров,
  - умеренная нагрузка, баланс между скоростью и глубиной.

- `aggressive` – максимальная глубина:
  - больше попыток выявления BOLA/IDOR и инъекций,
  - расширенное обнаружение скрытых эндпоинтов,
  - более интенсивные проверки каждого GOST-сканера.

### Безопасность и аккуратность:

- В режиме `aggressive` по умолчанию включены:
  - троттлинг запросов на уровне HttpClient (задержка между запросами),
  - автоматическое управление параллелизмом для снижения нагрузки на целевую систему,
  - соблюдение лимитов операций (`--max-exploit-ops`).
  
- Опция `--mask-secrets` (по умолчанию включена) защищает от случайной утечки токенов и чувствительных данных в логах и отчётах.

- **AI-обогащение** (`--ai-enabled`) рекомендуется для получения детальных рекомендаций и уточнения критичности находок.

---

## Ограничения и дальнейшее развитие

Текущая версия ориентирована на:
- один JWT‑токен (одна роль/один пользователь),
- HTTP‑интерфейсы, описанные в OpenAPI 3.0/3.1,
- специализированные GOST-сканеры для API-безопасности,
- OpenRouter как провайдера для AI‑обогащения (опционально).

### Потенциальные направления развития:

- Поддержка сценариев с несколькими ролями/пользователями для более комплексной проверки BOLA/BFLA.
- Расширение генерации тестовых данных по OpenAPI (body/query‑варианты, boundary‑cases).
- Интеграция с другими AI‑провайдерами (помимо OpenRouter).
- Дополнительные специализированные сканеры для конкретных доменов (FAPI, PSD2, и др.).
- Экспорт результатов в дополнительные форматы и интеграция с SIEM-системами.

### Текущее состояние:

API Defender уже сейчас обеспечивает удобный и глубокий аудит безопасности REST API, используя:
- контрактные проверки по OpenAPI,
- специализированные GOST-сканеры для выявления типичных уязвимостей,
- оценку риска по OWASP Risk Rating,
- опциональное AI‑обогащение для получения рекомендаций на русском языке.
