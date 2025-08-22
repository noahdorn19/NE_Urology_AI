import os, json, sqlite3
from contextlib import contextmanager

BACKEND = os.getenv("PROVIDERS_BACKEND", "sqlite").lower()
DB_PATH = os.getenv("PROVIDERS_DB", "providers.db")
JSON_PATH = os.getenv("PROVIDERS_JSON", "providers.json")

@contextmanager
def _conn():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        yield con
    finally:
        con.close()

def init():
    if BACKEND == "sqlite":
        with _conn() as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS providers(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  npi TEXT UNIQUE,
                  name TEXT,
                  dept TEXT,
                  meta TEXT
                )
            """)
            con.commit()
    else:
        if not os.path.exists(JSON_PATH):
            with open(JSON_PATH, "w") as f:
                json.dump({"providers": []}, f, indent=2)

def list_all(dept: str | None = None):
    if BACKEND == "sqlite":
        with _conn() as con:
            if dept:
                rows = con.execute("SELECT * FROM providers WHERE dept=?", (dept,)).fetchall()
            else:
                rows = con.execute("SELECT * FROM providers").fetchall()
        return [dict(r) for r in rows]
    data = json.load(open(JSON_PATH))
    items = data.get("providers", [])
    return [p for p in items if (not dept or (p.get("dept") == dept))]

def upsert(npi: str, name: str, dept: str | None = None, meta: dict | None = None):
    meta_s = json.dumps(meta or {})
    if BACKEND == "sqlite":
        with _conn() as con:
            con.execute("""
                INSERT INTO providers(npi, name, dept, meta) VALUES(?,?,?,?)
                ON CONFLICT(npi) DO UPDATE SET
                  name=excluded.name,
                  dept=excluded.dept,
                  meta=excluded.meta
            """, (npi, name, dept, meta_s))
            con.commit()
        return
    # JSON fallback
    data = json.load(open(JSON_PATH))
    arr = data.get("providers", [])
    for i, p in enumerate(arr):
        if p.get("npi") == npi:
            arr[i] = {"npi": npi, "name": name, "dept": dept, "meta": meta or {}}
            break
    else:
        arr.append({"npi": npi, "name": name, "dept": dept, "meta": meta or {}})
    data["providers"] = arr
    json.dump(data, open(JSON_PATH, "w"), indent=2)

def delete(npi: str):
    if BACKEND == "sqlite":
        with _conn() as con:
            con.execute("DELETE FROM providers WHERE npi=?", (npi,))
            con.commit()
        return
    data = json.load(open(JSON_PATH))
    arr = [p for p in data.get("providers", []) if p.get("npi") != npi]
    data["providers"] = arr
    json.dump(data, open(JSON_PATH, "w"), indent=2)