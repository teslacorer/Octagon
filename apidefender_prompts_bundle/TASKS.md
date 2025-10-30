# Task Decomposition (for the Agent, EN)

1. Bootstrap Maven multi-module; add Java 21, dependencies, quality plugins.
2. Implement core runner, config, token loader, HTTP client, concurrency control, timeout.
3. Implement OpenAPI loading (JSON/YAML), strict validation, behavior diff.
4. Implement undocumented discovery.
5. Implement scanner SPI, then scanners: bola, idor, injection, auth, excess-data (+ cors/headers/ratelimit/mass-assignment/errors).
6. Implement reporting: JSON (schema), HTML, PDF.
7. Implement logging JSONL, masking, trace saving.
8. Implement CLI flags and RU help texts; presets.
9. Dockerize (amd64/arm64), entrypoint, examples.
10. Add tests (unit + smoke + time budget).
11. Polish docs and examples.
