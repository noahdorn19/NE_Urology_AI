#!/usr/bin/env bash
set -euo pipefail

# --- Paths (adjust if your project lives elsewhere) ---
BASE="${BASE:-$HOME/Desktop/NE_Urology_AI}"
cd "$BASE"

# Databases
export RULES_DB="${RULES_DB:-$BASE/rules.db}"
AI_REF_DB="${AI_REF_DB:-$BASE/ai_ref.db}"

# Admin token for reindex (optional; only used if set)
ADMIN_TOKEN="${ADMIN_TOKEN:-}"

echo "== Using =="
echo "BASE        : $BASE"
echo "RULES_DB    : $RULES_DB"
echo "AI_REF_DB   : $AI_REF_DB"
echo

# --- 1) Create/ensure scheduling_rules table ---
sqlite3 "$RULES_DB" <<'SQL'
CREATE TABLE IF NOT EXISTS scheduling_rules(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_id TEXT UNIQUE,
  topic TEXT,
  description TEXT,
  allowed_roles TEXT,
  allowed_providers TEXT,
  disallowed_providers TEXT,
  disallowed_roles TEXT,
  conditions TEXT,
  enforce INTEGER DEFAULT 1,
  status TEXT DEFAULT 'ready',
  source TEXT
);
SQL

# --- 2) Add OCR columns only if they are missing ---
# Add OCR columns only if they are missing
if ! sqlite3 "$RULES_DB" "SELECT 1 FROM pragma_table_info('scheduling_rules') WHERE name='ocr_text' LIMIT 1;" | grep -q 1; then
  sqlite3 "$RULES_DB" "ALTER TABLE scheduling_rules ADD COLUMN ocr_text TEXT;"
fi
if ! sqlite3 "$RULES_DB" "SELECT 1 FROM pragma_table_info('scheduling_rules') WHERE name='ocr_last_updated' LIMIT 1;" | grep -q 1; then
  sqlite3 "$RULES_DB" "ALTER TABLE scheduling_rules ADD COLUMN ocr_last_updated TEXT;"
fi
if ! sqlite3 "$RULES_DB" "SELECT 1 FROM pragma_table_info('scheduling_rules') WHERE name='ocr_source_path' LIMIT 1;" | grep -q 1; then
  sqlite3 "$RULES_DB" "ALTER TABLE scheduling_rules ADD COLUMN ocr_source_path TEXT;"
fi

# --- 3) OPTIONAL: seed categories from categories.txt (one topic per line) ---
if [[ -f "categories.txt" ]]; then
  echo "Seeding categories from categories.txt..."
  while IFS= read -r topic; do
    [[ -z "$topic" ]] && continue
    rid="$(echo "$topic" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/_/g; s/^_|_$//g')"
    sqlite3 "$RULES_DB" <<SQL
INSERT OR REPLACE INTO scheduling_rules
(rule_id, topic, description, allowed_roles, allowed_providers, disallowed_providers, disallowed_roles, conditions, enforce, status, source)
VALUES
('$rid', '$topic', COALESCE((SELECT description FROM scheduling_rules WHERE rule_id='$rid'), ''),
 NULL, NULL, NULL, NULL, NULL, 1,
 COALESCE((SELECT status FROM scheduling_rules WHERE rule_id='$rid'), 'draft'),
 COALESCE((SELECT source FROM scheduling_rules WHERE rule_id='$rid'), 'Scheduling Decision Tree.xlsx'));
SQL
  done < categories.txt
fi

# --- 4) OPTIONAL: import rules from CSV if present (rules_seed.csv) ---
# CSV columns expected:
# rule_id, topic, description, allowed_roles, allowed_providers, disallowed_providers, disallowed_roles, conditions, enforce, status, source
if [[ -f "rules_seed.csv" ]]; then
  echo "Importing rules from rules_seed.csv..."
  sqlite3 "$RULES_DB" <<'SQL'
CREATE TABLE IF NOT EXISTS _import_rules_csv(
  rule_id TEXT, topic TEXT, description TEXT, allowed_roles TEXT,
  allowed_providers TEXT, disallowed_providers TEXT, disallowed_roles TEXT,
  conditions TEXT, enforce INTEGER, status TEXT, source TEXT
);
DELETE FROM _import_rules_csv;
SQL
  sqlite3 "$RULES_DB" <<'SQL'
.mode csv
.import rules_seed.csv _import_rules_csv
.quit
SQL
  sqlite3 "$RULES_DB" <<'SQL'
INSERT OR REPLACE INTO scheduling_rules
(rule_id, topic, description, allowed_roles, allowed_providers, disallowed_providers, disallowed_roles, conditions, enforce, status, source)
SELECT rule_id, topic, description, allowed_roles, allowed_providers, disallowed_providers, disallowed_roles, conditions, enforce, status, source
FROM _import_rules_csv;
DROP TABLE _import_rules_csv;
SQL
fi

# --- 5) Backfill OCR text for spreadsheet source from ai_ref.db ---
if [[ -f "$AI_REF_DB" ]]; then
  echo "Backfilling OCR text from ai_ref.db..."
  sqlite3 "$RULES_DB" <<SQL
ATTACH DATABASE '$AI_REF_DB' AS ref;

UPDATE scheduling_rules
SET
  ocr_text = (
    SELECT f.text_preview
    FROM ref.files f
    WHERE LOWER(f.path) LIKE '%scheduling decision tree.xlsx'
    ORDER BY f.id DESC
    LIMIT 1
  ),
  ocr_last_updated = (datetime('now')),
  ocr_source_path = 'Scheduling Decision Tree.xlsx'
WHERE LOWER(IFNULL(source,'')) = 'scheduling decision tree.xlsx';

DETACH DATABASE ref;
SQL
else
  echo "WARN: $AI_REF_DB not found; skipping OCR backfill."
fi

# --- 6) Purge scheduling_rules.json from catalog DB so RAG never returns it ---
if [[ -f "$AI_REF_DB" ]]; then
  echo "Purging scheduling_rules.json from ai_ref.db catalog..."
  sqlite3 "$AI_REF_DB" \
    "DELETE FROM files WHERE LOWER(path) LIKE '%/scheduling_rules.json' OR LOWER(path) LIKE '%\\scheduling_rules.json';"
fi

# --- 7) Show a quick count ---
echo
echo "Rule count / sample:"
sqlite3 "$RULES_DB" "SELECT COUNT(*), MIN(topic), MAX(topic) FROM scheduling_rules;"
sqlite3 "$RULES_DB" "SELECT topic, substr(ocr_text,1,80) AS ocr_excerpt FROM scheduling_rules WHERE ocr_text IS NOT NULL LIMIT 3;"

# --- 8) Reindex and restart app (optional) ---
echo
#echo "Restarting server..."
#pkill -9 -f "uvicorn.*chatbot_app" || true
#pkill -9 -f "watchfiles" || true
# Relaunch (comment this out if you run it another way)
#nohup uvicorn chatbot_app:app --host 127.0.0.1 --port 8003 --reload >/tmp/nu_uvicorn.out 2>&1 & disown

# Trigger reindex via admin endpoint if token present
if [[ -n "$ADMIN_TOKEN" ]]; then
  echo "Triggering /admin/reindex..."
  curl -s -X POST "http://127.0.0.1:8003/admin/reindex" -H "X-Admin-Token: $ADMIN_TOKEN" || true
fi

echo
echo "Done. RULES_DB: $RULES_DB"