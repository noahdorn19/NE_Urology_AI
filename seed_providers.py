# seed_providers.py
from providers_db import SessionLocal, Provider, ProviderAlias, AmbiguityRule, init_db
from sqlalchemy import select
from datetime import datetime

SEED = [
    ("DLH", "Dr. Don Henslee", "MD"),
    ("BLH", "Dr. Brandon Henslee", "MD"),
    ("AJL", "Dr. Lepinski", "MD"),
    ("AJP", "Dr. Pomajzl", "MD"),
    ("JRH", "Dr. Henning", "MD"),
    ("DBW", "Dr. Wiltfong", "MD"),
    ("LAW", "Dr. Wiebusch", "MD"),
    ("TPB", "Dr. Brush", "MD"),
    ("TMK", "Dr. Kirkpatrick", "MD"),
    ("LWM", "Dr. McGuffey", "MD"),

    ("SCM", "Simone Martin", "MSN, APRN"),
    ("KMW", "Katherine Wolverton", "DNP, FNP, APRN-NP"),
    ("CTB", "Casey Bock", "PA-C"),
    ("HBS", "Heidi Beynon-Solano", "PA-C"),
    ("TAW", "Tiffany Wood", "PA-C, MPAS"),
    ("JGO", "Jackie O'Doherty", "PA-C"),
    ("JDW", "Julie Wilson", "APRN-NP"),
    ("JLC", "Jacob Creevan", "PA-C"),
    ("LBL", "Lillie Lueke", "DNP, APRN"),
    ("ADS", "Ashley Sealy", "MSN, FNP-C, RDN, LMNT"),
    ("AKC", "Amy Collingham", "DNP, APRN, FNP-C"),
]

ALIAS_SEED = {
    "DLH": ["Don Henslee", "D. Henslee"],
    "BLH": ["Brandon Henslee", "B. Henslee"],
    "LAW": ["Lance Wiebusch"],
    "TPB": ["Thomas Brush"],
    "TMK": ["Tara Kirkpatrick"],
    "LWM": ["Logan McGuffey"],
    "DBW": ["David Wiltfong"],
    "JRH": ["Jonathan Henning"],
    "AJP": ["AJ Pomajzl"],
    "AJL": ["Andrew Lepinski"],
    # ... add more lightweight aliases as desired
}

AMBIG = [
    ("dr. henslee", "Did you mean Dr. Don Henslee (father) or Dr. Brandon Henslee (son)?", "DLH,BLH"),
    ("henslee", "Did you mean Dr. Don Henslee (father) or Dr. Brandon Henslee (son)?", "DLH,BLH"),
]

def norm(s: str) -> str:
    return s.strip().lower()

def run():
    init_db()
    db = SessionLocal()
    try:
        # Providers
        for abbr, name, role in SEED:
            existing = db.execute(select(Provider).where(Provider.abbr == abbr)).scalar_one_or_none()
            if not existing:
                p = Provider(abbr=abbr, full_name=name, role=role)
                db.add(p)
                db.flush()
                for alias in ALIAS_SEED.get(abbr, []):
                    db.add(ProviderAlias(provider_id=p.id, alias=alias, normalized=norm(alias), confidence=1.0))
        # Ambiguity rules
        for trig, prompt, csv_ in AMBIG:
            exists = db.execute(select(AmbiguityRule).where(AmbiguityRule.trigger == norm(trig))).scalar_one_or_none()
            if not exists:
                db.add(AmbiguityRule(trigger=norm(trig), prompt=prompt, abbrs_csv=csv_))
        db.commit()
    finally:
        db.close()

if __name__ == "__main__":
    run()