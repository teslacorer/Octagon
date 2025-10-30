# Prompt Guide for the Code Agent (EN)

- Keep all user-facing strings **in Russian**.
- Follow `REPORT_SCHEMA.json` exactly.
- Prefer clear modular code; document non-obvious decisions.
- Respect the global timeout and preset policies.
- Log in JSONL and always mask JWT before writing.
- Ensure Docker entrypoint works as shown in README.
