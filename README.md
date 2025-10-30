# API Defender (Java 21)

Инструмент командной строки для аудита API по OpenAPI и OWASP API Security Top‑10. Все пользовательские сообщения на русском. Скан завершается за ≤ 5 минут для ~60–70 эндпоинтов (профиль `full`).

## Быстрый старт (Docker)

1. Собрать образ:

```
docker build -t apidefender:local -f docker/Dockerfile .
```

2. Запустить скан (смонтируйте спецификацию и токен):

```
docker run --rm \
  -v %CD%/openapi.json:/app/specs/openapi.json \
  -v %CD%/token.jwt:/secrets/token.jwt \
  -v %CD%/out:/out \
  apidefender:local \
  scan \
  --openapi /app/specs/openapi.json \
  --token-file /secrets/token.jwt \
  --preset full \
  --timeout 5m \
  --report-html /out/report.html \
  --report-pdf /out/report.pdf \
  --report-json /out/report.json \
  --save-traces /out/traces \
  --log-file /out/scan.log \
  --base-url https://vbank.open.bankingapi.ru/
```

По завершении отчёты будут в каталоге `out/` и трейсы в `out/traces`.

## Ключевые флаги

- `--openapi /app/specs/openapi.json` — путь к OpenAPI (JSON/YAML)
- `--token-file /secrets/token.jwt` — файл с JWT клиента
- `--preset [fast|full|aggressive]` — профиль сканирования
- `--timeout 5m` — общий таймаут
- `--concurrency N` — параллелизм
- `--report-{html,pdf,json}` — пути вывода отчётов
- `--save-traces /out/traces` — каталог raw‑трейсов
- `--log-level [info|debug]` — уровень логов (JSONL)
- `--discover-undocumented` — поиск неописанных эндпоинтов (вкл.)
- `--strict-contract` — строгая проверка контракта (вкл.)

## Примечания

- Отчёт JSON соответствует схеме `apidefender_prompts_bundle/REPORT_SCHEMA.json`.
- JWT маскируется в логах и трейсах.
- Предусмотрены базовые проверки: контракт, неописанные эндпоинты, CORS/безопасные заголовки, слабая аутентификация. Расширяйте сканеры по необходимости.
