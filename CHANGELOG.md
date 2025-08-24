# NE_Urology_AI — Release Notes

## Version 0.18.1 — 2025-08-23

This release adds major improvements to grounding, synonym learning, and reflexive AI answering.

### 🚀 New Features
- **Two-pass autoregressive self-check (`_generate_with_self_check`)**
  - AI now generates a draft, then reviews its own output for hallucinations, grounding violations, and contradictions.
  - Enforces context-only answers, with concise corrections and clarifying questions if uncertain.

- **Synonym learning & confirmation loop**
  - Added `synonym_map` table in `rules.db` with support for:
    - Confidence scoring, weight, last_used, and feedback learning.
  - New `expand_with_synonyms()` function augments user queries with canonical terms for better DB/file matching.
  - AI can now propose synonym mappings:
    - User confirms with **yes** → stored as a learned synonym.
    - User corrects with **“no, I meant …”** → updates synonym map accordingly.
  - Added `/feedback` endpoint for structured feedback (observed, canonical, rating, comment).

- **Database context integration**
  - `load_rule_matches()` searches `scheduling_rules` in `rules.db` (topic, description, OCR text).
  - `load_related_rules()` provides fuzzy/related rule matches when no exact match is found.
  - Rules from DB are treated as **authoritative over file OCR** when both are present.

- **Provider context lookup**
  - Provider abbreviations (e.g., TPB, DLH, BLH) resolved via `providers.db`.
  - AI now injects “Provider Context” blocks automatically when providers are detected in user messages.

- **Image integration**
  - New endpoints:
    - `/api/xlsx_image_raw` → return embedded `.xlsx` image bytes.
    - `/view/xlsx_images` → render sheet-level HTML galleries of workbook images.
  - Chat responses automatically prepend relevant images from **Scheduling Decision Tree.xlsx** or the hit `.xlsx`.

- **Startup refresh**
  - On `startup`, `refresh_rules_from_ai_ref()` runs:
    - Imports OCR previews from `ai_ref.db` into `rules.db`.
    - Keeps `scheduling_rules` in sync with the latest ingested content.

- **System profiles (modular prompts)**
  - Three selectable styles: `strict_rag`, `guided_grounded` (default), `general`.
  - Runtime switching via `/admin/system_profile` with `X-Admin-Token`.
  - Profiles adjust how AI handles hits, grounding, and clarification questions.

### 🛠 Improvements
- **Chat flow** now checks **DB context → Provider context → File hits** in order of authority.
- Introduced **“Possibly related”** section when no direct match is found.
- Config JSON mentions (`scheduling_rules.json`) are sanitized into human-readable source names.
- Session-specific synonym confirmation handled via `PENDING_SYNONYM`.
- Structured context block assembly ensures cumulative inclusion of DB, provider, and file matches.

### 🐛 Fixes
- Fixed incorrect SQL parameter binding in `load_related_rules()`.
- Ensured catalog ignores unchanged files unless forced.
- Startup no longer fails when `scheduling_rules` table missing — auto-creates if absent.
- Improved ACL checks for `.xlsx` images to respect user department restrictions.

---

🔖 **Summary:**  
Version 0.18.1 introduces **self-refining AI answers, synonym learning, and multi-source grounding (DB + providers + OCR)**, making the assistant significantly more accurate and adaptive for schedulers and staff.

This version is not yet production ready and remains in prototype/testing phase. Version 1.0.0 is planned as the first stable release.