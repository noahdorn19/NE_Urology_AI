## Version 0.18.2 — 2025-08-24

⚠️ Status: Prototype/Testing Only  
This version is **not yet production ready**. It remains in the testing phase. Version 1.0.0 is still planned as the first stable release.

### 🚀 New Features
- **Self-research fallback**  
  Added an “auto research” layer where the AI digs deeper into OCR/Excel/DB content if direct matches aren’t found.
- **Expanded synonym learning**  
  - Synonym map now supports auto-expansion of user queries (“unable to urinate” → “urinary retention”).  
  - Confirmation prompts added so users can correct or approve synonyms mid-conversation.
- **Rule DB integration upgrades**  
  - Scheduling rules from OCR/EMF scans are now synced into `rules.db`, not just JSON.  
  - Added ability to include OCR/EMF text alongside structured scheduling rules.
- **Context block assembly improvements**  
  - Responses now include **cumulative context**: DB context + provider context + file hits, instead of either/or.  
  - “Possibly related” section appears when no strong match is found.
- **Provider disambiguation**  
  - AI now asks clarifying questions (e.g., “Dr. Don Henslee or Dr. Brandon Henslee?”) when abbreviations are ambiguous.
- **Image integration in chat**  
  - Relevant Excel `.emf`/image previews are shown inline with AI’s textual reasoning.  
  - Sheet-level image galleries available at `/view/xlsx_images`.
- **Feedback loop groundwork**  
  - `/feedback` endpoint extended to allow user corrections to be stored and improve synonym mappings/rule alignment.
- **Startup sync updates**  
  - Improved `refresh_rules_from_ai_ref()` and index rebuilds so rules/images/embeddings always sync at app boot.

### 🛠 Improvements
- Removed all reliance on `scheduling_rules.json`; rules now come **only from `rules.db`**.  
- AI responses are rephrased to address staff directly (first person), rather than describing actions in third person.  
- AI now gracefully handles “close but not exact” matches — tries synonyms, related rules, or research before giving up.  
- Stability fixes for crashes caused by wrong `simple_search` arguments and missing `structured_block`.

### 🐛 Fixes
- Fixed indentation errors in `chatbot_app.py`.  
- Corrected SQL binding issues in `load_related_rules()`.  
- Removed invalid `root=AI_REF_ROOT` calls in `simple_search`.  
- Added missing safety checks so the app won’t crash if OCR/structured fields aren’t populated.

---

🔖 **Summary:**  
Version 0.18.2 makes the AI **smarter, more resilient, and more user-friendly** by introducing synonym learning, auto-research, inline images, and stronger DB grounding. It is still in **prototype phase** and not production-ready.