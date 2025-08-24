import os, re, json, sqlite3, datetime
from pathlib import Path

BASE = Path(__file__).parent
RULES_DB = os.getenv("RULES_DB", str(BASE / "rules.db"))
AI_REF_ROOT = os.getenv("AI_REF_ROOT", str((BASE / "ai_reference").resolve()))

# Point this to your actual path under ai_reference:
# e.g. ai_reference/global/Scheduling Decision Tree.xlsx.txt
DEFAULT_TXT = os.getenv("SDT_TXT_PATH", "global/Scheduling Decision Tree.xlsx.txt")

HEAD_RE = re.compile(r"""
    ^\s*
    (?:[A-Z0-9]{1,3}[)\.\-:]?\s+|              # A), A., A-, A:
     \[[A-Za-z0-9]+\]\s+|                      # [A], [1]
     #{1,3}\s+|                                # markdown-ish ### Section
     (?:Sheet:|Section:)\s+)?
    (?P<title>[A-Z][A-Za-z0-9/ &,\-\(\)]+)     # Title-like
    \s*$
""", re.X)

SHEET_HINT = re.compile(r"(?:sheet|tab)\s*[:\-]\s*([A-Za-z0-9 _\-\(\)]+)", re.I)

def slug(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "_", s).strip("_")
    return s[:80] or "untitled"

def find_txt():
    # Prefer env-provided relative path under ai_reference
    p = Path(AI_REF_ROOT) / DEFAULT_TXT
    if p.exists():
        return p
    # Otherwise, search for any “…Decision Tree.xlsx.txt”
    candidates = list(Path(AI_REF_ROOT).rglob("*Decision Tree.xlsx.txt"))
    return candidates[0] if candidates else None

def split_sections(full_text: str):
    lines = full_text.splitlines()
    sections = []
    cur_title, cur_buf = None, []
    for ln in lines:
        m = HEAD_RE.match(ln)
        if m:
            # flush previous
            if cur_title and cur_buf:
                sections.append((cur_title.strip(), "\n".join(cur_buf).strip()))
            cur_title = m.group("title").strip()
            cur_buf = []
        else:
            cur_buf.append(ln)
    if cur_title and cur_buf:
        sections.append((cur_title.strip(), "\n".join(cur_buf).strip()))
    return sections

def infer_sheet(text_block: str, fallback_title: str):
    m = SHEET_HINT.search(text_block)
    if m:
        return m.group(1).strip()
    # heuristic: if title looks like a tab (Title – something)
    parts = re.split(r"[–-]", fallback_title)
    if len(parts) >= 2 and len(parts[0]) <= 30:
        return parts[0].strip()
    return None

def main():
    txt_path = find_txt()
    if not txt_path:
        raise SystemExit("Could not locate Scheduling Decision Tree.xlsx.txt under ai_reference.")
    rel_src = str(txt_path.relative_to(AI_REF_ROOT))
    full_text = txt_path.read_text(errors="ignore")
    secs = split_sections(full_text)
    if not secs:
        raise SystemExit("No sections found; adjust HEAD_RE if needed.")

    conn = sqlite3.connect(RULES_DB)
    cur = conn.cursor()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")

    upserts = 0
    for title, body in secs:
        rule_id = f"sdt_{slug(title)}"
        sheet = infer_sheet(body, title)
        topic = title
        description = (body[:2000]).strip()  # short description from section body

        cur.execute("""
        INSERT INTO scheduling_rules
          (rule_id, topic, description, source, enforce, status,
           ocr_text, ocr_sheet, ocr_last_updated, source_path)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(rule_id) DO UPDATE SET
           topic=excluded.topic,
           description=excluded.description,
           source=excluded.source,
           ocr_text=excluded.ocr_text,
           ocr_sheet=excluded.ocr_sheet,
           ocr_last_updated=excluded.ocr_last_updated,
           source_path=excluded.source_path,
           status='updated'
        """, (
            rule_id, topic, description,
            "Scheduling Decision Tree.xlsx",
            1, "draft",
            body, sheet, now, rel_src
        ))
        upserts += 1

    conn.commit()
    conn.close()
    print(f"Imported/updated {upserts} rule sections from {rel_src}")

if __name__ == "__main__":
    main()