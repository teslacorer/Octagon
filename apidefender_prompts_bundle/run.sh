#!/usr/bin/env bash
# Подсказка запуска (реальную команду сгенерирует агент)
docker run --rm \
  -v "$PWD/out:/out" \
  -v "$PWD/openapi.json:/app/specs/openapi.json" \
  -v "$PWD/token.jwt:/secrets/token.jwt" \
  apidefender:local scan --preset full --timeout 5m
