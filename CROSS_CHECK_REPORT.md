# NightCrawler Cross-Check Report

The alternate implementation correctly exposed the original GET duplicate-query false negative and broadened payload coverage. It was not copied wholesale because parts of it regressed stronger safeguards already present in the release candidate.

## Merged improvements

- GET payloads replace targeted query parameters instead of appending duplicates.
- Query-parameter endpoints are retained for non-HTML/API responses.
- Broader payload files were adopted except destructive database-modification probes.
- Credential-field detection and its outer execution gate are consistent.
- Sensitive absolute paths are handled at the target origin.

## Safeguards retained

- Untrusted target data is isolated from AI instructions.
- AI output is schema validated.
- Redirect responses are preserved for analysis.
- HSTS checks are HTTPS-aware.
- CLI validation and API-key secrecy remain enforced.
- Report output is autoescaped and severity ordering is deterministic.

## Provider change

The final release uses Google Gemini instead of Claude. The provider change is isolated to `modules/ai_brain.py`, configuration, reporting labels, tests, and documentation; crawler, attacker, payload, and report contracts remain unchanged.
