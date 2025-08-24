# migrate_rules_table.py
import os, sqlite3, sys
from pathlib import Path

DB = Path(os.getenv("RULES_DB", "rules.db")).resolve()

REQUIRED_COLS = {
    "ocr_text":        "TEXT",
    "ocr_sheet":       "TEXT",
    "ocr_last_updated":"TEXT",
    "source_path":     "TEXT"
}

def main():
    conn = sqlite3.connect(str(DB))
    cur = conn.cursor()
    # ensure table exists
    cur.execute("""
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
    """)
    # what columns are present?
    cols = {r[1] for r in cur.execute("PRAGMA table_info(scheduling_rules)").fetchall()}
    added = []
    for name, decl in REQUIRED_COLS.items():
        if name not in cols:
            cur.execute(f"ALTER TABLE scheduling_rules ADD COLUMN {name} {decl};")
            added.append(name)
    conn.commit()
    conn.close()
    print(f"OK: {DB} migrated. Added: {', '.join(added) if added else '(none)'}")

if __name__ == "__main__":
    main()