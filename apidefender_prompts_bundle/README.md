# API Defender (VBank) — сканер контракта и безопасности

**Коротко:** CLI-утилита на Java 21 для проверки соответствия OpenAPI и поиска уязвимостей OWASP API Top-10. Генерирует HTML, PDF и JSON отчёты. Запуск через Docker, ≤ 5 минут на ~60–70 эндпоинтов.

## Быстрый старт
```bash
docker build -t apidefender:local -f docker/Dockerfile .
docker run --rm \
  -v "$PWD/out:/out" \
  -v "$PWD/openapi.json:/app/specs/openapi.json" \
  -v "$PWD/token.jwt:/secrets/token.jwt" \
  apidefender:local scan \
  --openapi /app/specs/openapi.json \
  --token-file /secrets/token.jwt \
  --preset full --timeout 5m
```

## Параметры CLI
См. `SPEC.md` → Раздел CLI. Подсказки доступны через `--help`.

## Отчёты и артефакты
- HTML: `/out/report.html`
- PDF: `/out/report.pdf`
- JSON: `/out/report.json`
- Трейсы запросов/ответов: `/out/traces` (JWT замаскировано)

## Безопасность и маскирование
Маскируется только JWT-токен. Остальные данные сохраняются как есть (по условиям).

## Телеметрия
Анонимная: длительность, кол-во эндпоинтов и проверок, латентность, доля несоответствий, распределение уязвимостей.
