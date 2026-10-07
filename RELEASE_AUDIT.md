# NightCrawler Final Release Audit

**Release candidate:** Gemini-backed NightCrawler
**Audit date:** October 7, 2026

## Final status

The release preserves the existing NightCrawler module architecture while incorporating verified fixes from the cross-check and a provider migration from Anthropic/Claude to Google Gemini. The unrelated `DSA.cpp` artifact was removed completely.

## Verified functional areas

- GET query-parameter replacement prevents duplicate-key false negatives.
- Query-parameter endpoints are discovered even when the target response is JSON/text rather than HTML.
- Authentication probing is gated consistently for `password`, `pwd`, `secret`, `token`, and related credential fields.
- Sensitive absolute paths remain rooted at the target origin; relative paths remain under the target application path.
- Security responses are not filtered by status, size, reflection, or keyword heuristics before AI analysis.
- Target response data is isolated as untrusted evidence in the AI prompt.
- AI results are schema-validated before reaching the reporting layer.
- Report output is HTML-escaped and severity sorted.
- `--no-pdf` is honored.
- API keys are loaded from environment variables and are never printed.

## Gemini integration

The AI provider now uses the documented Gemini `models.generateContent` REST endpoint with the `x-goog-api-key` header. Structured JSON output is requested using `responseMimeType=application/json` and `responseSchema`; system instructions are supplied separately. No additional Google SDK dependency is required because the project already depends on `requests`. Google currently lists `gemini-3.8-flash` as a stable Gemini 3 model and its current pricing page shows the standard Free Tier as free of charge, subject to applicable limits.

## Test verification

The final tree passes **13/13** automated tests, Python compilation, a mocked full CLI crawl → attack → Gemini → report pipeline, report escaping/order checks, query replacement regressions, API/non-HTML endpoint discovery, and release-tree cleanliness checks.

A real Gemini API call is intentionally left to the user's machine because the API credential is private. The live smoke-test command is documented separately in the release handoff.
