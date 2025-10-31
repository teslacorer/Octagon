# API Defender (Java 21, CLI)

Инструмент для аудита API по OpenAPI и проверок безопасности (OWASP API Security Top‑10). Работает в Docker, генерирует HTML, PDF и JSON отчеты. Поддерживает пресеты скорости/глубины: fast, full (по умолчанию), aggressive.

## Сборка (Docker)

1) Соберите образ:

```
docker build -t apidefender:local -f docker/Dockerfile .
```

## Запуск сканирования (CLI)

Минимальный пример (Windows PowerShell):

```
docker run --rm \
  -v "${PWD}/openapi.json:/app/specs/openapi.json" \
  -v "${PWD}/token.jwt:/secrets/token.jwt" \
  -v "${PWD}/out:/out" \
  apidefender:local scan \
  --openapi /app/specs/openapi.json \
  --token-file /secrets/token.jwt \
  --base-url https://vbank.open.bankingapi.ru/ \
  --preset full \
  --timeout 5m \
  --report-html /out/report.html \
  --report-pdf /out/report.pdf \
  --report-json /out/report.json \
  --save-traces /out/traces \
  --log-file /out/scan.log \
  --log-level info
```

Пример (Linux/macOS, bash/zsh):

```
docker run --rm \
  -v "$PWD/openapi.json:/app/specs/openapi.json" \
  -v "$PWD/token.jwt:/secrets/token.jwt" \
  -v "$PWD/out:/out" \
  apidefender:local scan \
  --openapi /app/specs/openapi.json \
  --token-file /secrets/token.jwt \
  --base-url https://vbank.open.bankingapi.ru/ \
  --preset full \
  --timeout 5m \
  --report-html /out/report.html \
  --report-pdf /out/report.pdf \
  --report-json /out/report.json \
  --save-traces /out/traces \
  --log-file /out/scan.log \
  --log-level info
```

Пример “агрессивного” запуска:

```
docker run --rm \
  -v "${PWD}/openapi.json:/app/specs/openapi.json" \
  -v "${PWD}/token.jwt:/secrets/token.jwt" \
  -v "${PWD}/out:/out" \
  apidefender:local scan \
  --openapi /app/specs/openapi.json \
  --token-file /secrets/token.jwt \
  --base-url https://abank.open.bankingapi.ru/ \
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
```

## Параметры CLI (основные)

- `--openapi <path>` — путь к спецификации OpenAPI (JSON/YAML) внутри контейнера.
- `--base-url <url>` — базовый URL тестируемого API.
- `--token-file <path>` — путь к файлу с JWT (Bearer) внутри контейнера.
- `--preset <fast|full|aggressive>` — скорость/глубина проверки.
- `--timeout <dur>` — общий таймаут (например, `5m`, `30s`).
- `--concurrency <N>` — уровень параллелизма (по умолчанию авто).
- `--report-html|--report-pdf|--report-json <path>` — пути для отчетов.
- `--save-traces <dir>` — сохранять raw‑трейсы запросов/ответов.
- `--log-file <path>` — лог JSONL сканирования; `--log-level <info|debug>`.
- `--discover-undocumented` — попытка находить неописанные пути (включено по умолчанию).
- `--strict-contract` — строгая проверка контракта (включено по умолчанию).
- `--public-path <csv>` — список публичных путей без авторизации.
- `--allow-cors-wildcard-public` — разрешить `*` в CORS для публичных путей.
- `--safety-skip-delete` — пропуск опасных DELETE операций.
- `--exploit-depth <low|med|high>` и `--max-exploit-ops <N>` — глубина и лимиты активных проверок.

## Артефакты

- HTML/PDF/JSON отчеты — в смонтированной папке `out/`.
- Логи — `scan.log` (JSONL) в `out/`.
- Сырые трейсы — в `out/traces`.

## Примечания

- На Windows используйте PowerShell‑синтаксис с `${PWD}` и прямыми слэшами в путях маунтов.
- Файл `token.jwt` и `openapi.json` должны существовать на хосте и быть примонтированы в контейнер по указанным путям.

