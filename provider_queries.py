# provider_queries.py
from sqlalchemy import select
from providers_db import SessionLocal, Provider
from providers_prefs import ProviderPref

def get_provider_pref(abbr: str) -> dict | None:
    """Return merged provider info + prefs for one provider."""
    db = SessionLocal()
    try:
        p = db.execute(select(Provider).where(Provider.abbr == abbr)).scalar_one_or_none()
        if not p:
            return None
        pref = db.execute(select(ProviderPref).where(ProviderPref.provider_id == p.id)).scalar_one_or_none()
        return {
            "abbr": p.abbr,
            "name": p.full_name,
            "role": p.role,
            "children_policy": pref.children_policy if pref else None,
            "special_requests": pref.special_requests if pref else None,
            "on_call_routing": pref.on_call_routing if pref else None,
            "non_call_routing": pref.non_call_routing if pref else None,
            "pm_out": pref.pm_out if pref else None,
            "direct_phone": pref.direct_phone if pref else None,
            "er_dr_hospital_rules": pref.er_dr_hospital_rules if pref else None,
            "allows_vasectomy": pref.allows_vasectomy if pref else None,
            "sees_new_kids": pref.sees_new_kids if pref else None,
            "sees_pessary": pref.sees_pessary if pref else None
        }
    finally:
        db.close()


def can_book_vasectomy(abbr: str) -> str:
    """Return human-readable answer about vasectomy booking."""
    pref = get_provider_pref(abbr)
    if not pref:
        return f"I don’t have any record for provider {abbr}."
    if pref["allows_vasectomy"] is False:
        return f"{pref['name']} ({abbr}) does **not** accept vasectomy appointments (per provider preferences)."
    elif pref["allows_vasectomy"] is None:
        return f"No explicit vasectomy rule found for {pref['name']} ({abbr})."
    else:
        return f"{pref['name']} ({abbr}) accepts vasectomy appointments."


def can_see_kids(abbr: str) -> str:
    """Return human-readable answer about seeing children."""
    pref = get_provider_pref(abbr)
    if not pref:
        return f"I don’t have any record for provider {abbr}."
    if pref["sees_new_kids"] is False:
        return f"{pref['name']} ({abbr}) does **not** see children (per provider preferences)."
    elif pref["sees_new_kids"] is None:
        return f"No explicit rule about kids found for {pref['name']} ({abbr})."
    else:
        return f"{pref['name']} ({abbr}) sees children."