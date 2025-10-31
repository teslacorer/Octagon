# API Defender (Java 21, CLI)

Инструмент динамического тестирования безопасности API на основе спецификаций OpenAPI и набора проверок OWASP API Security. Поставляется как CLI и Docker-образ. Формирует подробные отчеты HTML, PDF и JSON, а также сохраняет трассы запросов и ответов.

Основные сценарии использования:
- Быстрая проверка API по OpenAPI на соответствие контракту (коды, Content-Type, схемы).
- Обнаружение недокументированных эндпоинтов (discovery).
- Набор встроенных сканеров: заголовки безопасности, CORS, слабая аутентификация, инъекции, rate limit, BOLA/IDOR, BFLA, HPP, Mass Assignment, Verbose Errors, Pagination и др.
- Автоматический расчет риска OWASP Risk Rating для каждой находки.

---

## Быстрый старт (Docker)

1) Сборка образа:

    docker build -t apidefender:local -f docker/Dockerfile .

2) Запуск (Windows PowerShell):

    docker run --rm \
      -v "<HOST_CWD>/openapi.json:/app/specs/openapi.json" \
      -v "<HOST_CWD>/token.jwt:/secrets/token.jwt" \
      -v "<HOST_CWD>/out:/out" \
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

3) Запуск (Linux/macOS, bash/zsh):

    docker run --rm \
      -v "<HOST_CWD>/openapi.json:/app/specs/openapi.json" \
      -v "<HOST_CWD>/token.jwt:/secrets/token.jwt" \
      -v "<HOST_CWD>/out:/out" \
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

Пример быстрой проверки с агрессивными параметрами:

    docker run --rm \
      -v "<HOST_CWD>/openapi.json:/app/specs/openapi.json" \
      -v "<HOST_CWD>/token.jwt:/secrets/token.jwt" \
      -v "<HOST_CWD>/out:/out" \
      apidefender:local scan \
      --openapi /app/specs/openapi.json \
      --token-file /secrets/token.jwt \
      --base-url https://api.example.com/ \
      --preset aggressive \
      --timeout 5m \
      --public-path /,/status,/health \
      --allow-cors-wildcard-public \
      --report-html /out/report_check_fast.html \
      --report-pdf /out/report_check_fast.pdf \
      --report-json /out/report_check_fast.json \
      --save-traces /out/traces_check_fast \
      --log-file /out/scan_check_fast.log \
      --log-level info \
      --safety-skip-delete \
      --exploit-depth med \
      --max-exploit-ops 40

---

## Локальная сборка и запуск (без Docker)

Требуется Java 21 и Maven 3.9+.

    mvn -DskipTests -pl apidefender-cli -am package
    java -jar apidefender-cli/target/apidefender-cli-*.jar scan \
      --openapi ./openapi.json \
      --token-file ./token.jwt \
      --base-url https://api.example.com/ \
      --preset full

---

## Параметры CLI

- --openapi <path> — путь к спецификации OpenAPI (JSON/YAML). По умолчанию: /app/specs/openapi.json.
- --base-url <url> — базовый URL целевого API (если не указан, берется из servers[0] спецификации, иначе http://localhost:8080).
- --token-file <path> (обяз.) — путь к файлу с JWT токеном (строка Bearer добавляется автоматически).
- --preset <fast|full|aggressive> — набор интенсивности проверок. По умолчанию: full.
- --timeout <dur> — общий таймаут сканирования (например, 30s, 5m, 1h). По умолчанию: 5m.
- --concurrency <N> — число потоков (по умолчанию: auto = max(2, CPU)).
- --report-html <path> — путь к HTML-отчету (по умолчанию: /out/report.html).
- --report-pdf <path> — путь к PDF-отчету (по умолчанию: /out/report.pdf).
- --report-json <path> — путь к JSON-отчету (по умолчанию: /out/report.json).
- --save-traces <dir> — директория для сохранения трасс запросов и ответов (по умолчанию: /out/traces).
- --log-file <path> — путь к JSONL логу (по умолчанию: /out/scan.log).
- --log-level <info|debug> — уровень логирования (по умолчанию: info).
- --discover-undocumented <true|false> — искать недокументированные эндпоинты (по умолчанию: true).
- --strict-contract <true|false> — строгая проверка соответствия контракту (по умолчанию: true).
- --public-path <csv> — список публичных префиксов путей (через запятую), влияет на CORS-проверки.
- --allow-cors-wildcard-public <true|false> — разрешить * в ACAO только на публичных путях (по умолчанию: true).
- --exploit-depth <low|med|high> — глубина попыток эксплуатации (по умолчанию зависит от пресета: fast=low, full=med, aggressive=high).
- --max-exploit-ops <N> — лимит попыток эксплуатации (по умолчанию: 40).
- --safety-skip-delete <true|false> — пропускать опасные операции DELETE (по умолчанию: true).
- --debug <true|false> — добавить подробный вывод в лог (по умолчанию: false).
- --mask-secrets <true|false> — маскировать секреты (JWT, токены) в трассах и логах (по умолчанию: true).
- --telemetry-endpoint <url> — URL для отправки анонимной телеметрии (опционально).
- --telemetry-opt-in <true|false> — включить отправку анонимной телеметрии (по умолчанию: false).

Производные параметры (задаются пресетом):
- idorMax — глубина проверок BOLA/IDOR (fast=2, full=6, aggressive=12).
- injectionOps — число payload-попыток для инъекций (fast=6, full=15, aggressive=30).
- rateBurst — серия запросов для проверки rate limit (fast=5, full=15, aggressive=40).

---

## Выходные артефакты

- Отчеты: report.html, report.pdf, report.json — в каталоге, заданном через --report-* (по умолчанию /out).
- Лог сканирования: scan.log — JSONL-формат (одно событие на строку).
- Трассы: директория traces/ — JSON с полными данными запроса и ответа. Маскирование секретов включается опцией --mask-secrets.

JSON-отчет содержит: метаданные запуска, несоответствия контракту, список уязвимостей (категория, описание, рекомендация, риск), телеметрию.

---

## Встроенные сканеры (неполный список)

- SecurityHeaders — проверка обязательных заголовков безопасности на корне (/).
- CORS — анализ Access-Control-Allow-Origin и связанных заголовков.
- WeakAuth — ответы без аутентификации или с невалидным токеном.
- Injection — инъекции (ошибки и тайминги) с ограниченным набором payload’ов и эвристик.
- RateLimit — отсутствие 429/RateLimit-заголовков при бурст-нагрузке.
- BOLA/IDOR — попытки доступа к объектам других пользователей.
- BFLA, HPP, MassAssignment, VerboseErrors, Pagination, MethodOverride и др.

Каждая находка автоматически получает оценку OWASP Risk Rating; итоговая severity синхронизируется с рассчитанным риском.

---

## Архитектура и ключевые директории

- apidefender-core/ — базовые компоненты:
  - core/Config.java — конфигурация (внутренняя модель).
  - core/http/HttpClient.java, core/http/Masking.java — HTTP и маскирование секретов.
  - core/openapi/OpenApiLoader.java — загрузка и парсинг OpenAPI.
  - core/report/ReportModel.java — модель отчета.
  - core/risk/RiskAssessor.java — расчет рисков OWASP.
  - core/log/JsonlLogger.java — JSONL-логгер.
- apidefender-scanners/ — интерфейс SPI и реализации сканеров:
  - scanners/SPI.java — контракт сканера и контекст сканирования.
  - scanners/simple/*, scanners/owasp/* — конкретные проверки.
- apidefender-reporting/ — генерация отчетов:
  - core/report/ReportWriter.java — запись JSON, HTML, PDF.
  - core/report/HtmlTemplates.java — HTML-шаблон отчета.
- apidefender-cli/ — CLI-утилита:
  - cli/Main.java — точка входа.
  - cli/commands/ScanCommand.java — основная команда scan и оркестрация сканирования.
- docker/Dockerfile — сборка образа.
- openapi.json — пример спецификации.
- out/ — дефолтная папка для результатов (монтируется в Docker).

Краткий обзор Maven:
- Родительский pom.xml — версии плагинов и зависимостей, список модулей.
- Модули: apidefender-core, apidefender-scanners, apidefender-reporting, apidefender-cli.

---

## Переменные окружения и файлы

- JWT-токен передается через файл опцией --token-file (например, ./token.jwt).
- При запуске в Docker примонтируйте:
  - openapi.json → /app/specs/openapi.json (чтение).
  - token.jwt → /secrets/token.jwt (чтение).
  - out/ → /out (запись отчетов, логов, трасс).
- Обязательных переменных окружения нет. 

---

## Замечания по безопасности

- Пресет aggressive может генерировать повышенную нагрузку и выявляющие payload’ы. 
- Включайте --mask-secrets (по умолчанию включено), чтобы скрывать токены и чувствительные данные в логах и трассах.
- Опция --safety-skip-delete предотвращает выполнение потенциально опасных DELETE (по умолчанию включено).

---