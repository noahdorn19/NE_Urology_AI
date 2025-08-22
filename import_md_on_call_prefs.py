# import_md_on_call_prefs.py
from pathlib import Path
from docx import Document
from sqlalchemy import select
from providers_db import SessionLocal, Provider, init_db
from providers_prefs import ProviderPref

DOC_PATH = Path("ai_reference/MD on call and appt preferences.docx")  # adjust if needed

def norm(s): return (s or "").strip()

def run():
    init_db()
    db = SessionLocal()
    try:
        doc = Document(str(DOC_PATH))
        # Assume the first table is the preferences table.
        table = doc.tables[0]

        # Build header map by column index → header name
        headers = [norm(cell.text).lower() for cell in table.rows[0].cells]

        # helper to get col by header contains text
        def col_idx(key):
            for i,h in enumerate(headers):
                if key in h:
                    return i
            return None

        c_name = col_idx("name")
        c_initials = col_idx("initials")
        c_children = col_idx("children")
        c_special = col_idx("special")
        c_oncall = col_idx("on call")
        c_noncall = col_idx("non-call")
        c_pmout = col_idx("pm out")
        c_phone = col_idx("phone")
        c_drser = col_idx("drs or er") or col_idx("drs") or col_idx("er")
        c_hosp_consult = col_idx("hospital routine consult")
        c_dr_call = col_idx("dr call")
        c_provider_call = col_idx("provider call")

        for r in table.rows[1:]:
            cells = r.cells
            name = norm(cells[c_name].text) if c_name is not None else ""
            abbr = norm(cells[c_initials].text) if c_initials is not None else ""

            if not abbr:  # skip blank rows
                continue

            prov = db.execute(select(Provider).where(Provider.abbr == abbr)).scalar_one_or_none()
            if not prov and name:
                # create provider stub if missing (lets you seed later)
                prov = Provider(abbr=abbr, full_name=name, role="MD")
                db.add(prov); db.flush()

            if not prov:
                continue

            pref = db.execute(select(ProviderPref).where(ProviderPref.provider_id == prov.id)).scalar_one_or_none()
            if not pref:
                pref = ProviderPref(provider_id=prov.id)
                db.add(pref)

            pref.children_policy   = norm(cells[c_children].text) if c_children is not None else None
            pref.special_requests  = norm(cells[c_special].text) if c_special is not None else None
            pref.on_call_routing   = norm(cells[c_oncall].text) if c_oncall is not None else None
            pref.non_call_routing  = norm(cells[c_noncall].text) if c_noncall is not None else None
            pref.pm_out            = norm(cells[c_pmout].text) if c_pmout is not None else None
            pref.direct_phone      = norm(cells[c_phone].text) if c_phone is not None else None

            # stitch related columns the doc has (ER, consults, dr call, provider call)
            lines = []
            if c_drser is not None:           lines.append("Drs/ER: " + norm(cells[c_drser].text))
            if c_hosp_consult is not None:    lines.append("Hospital consult: " + norm(cells[c_hosp_consult].text))
            if c_dr_call is not None:         lines.append("Dr call: " + norm(cells[c_dr_call].text))
            if c_provider_call is not None:   lines.append("Provider call: " + norm(cells[c_provider_call].text))
            pref.er_dr_hospital_rules = "\n".join([l for l in lines if l and l != "Label"]) or None

            pref.last_source = str(DOC_PATH)

            # lightweight flags (only when explicit)
            txt = " ".join([pref.special_requests or "", pref.children_policy or ""]).lower()
            pref.allows_vasectomy = False if "no vasectom" in txt else None
            if "no kids" in txt: pref.sees_new_kids = False
            if "pessary" in txt: pref.sees_pessary = True

        db.commit()
        print("Imported preferences from", DOC_PATH)
    finally:
        db.close()

if __name__ == "__main__":
    run()