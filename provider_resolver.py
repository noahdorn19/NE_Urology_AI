# provider_resolver.py
from typing import Dict, Any, List
from sqlalchemy import select
from providers_db import SessionLocal, Provider, ProviderAlias, AmbiguityRule

def _norm(s: str) -> str:
    return s.strip().lower()

def resolve_provider(query: str) -> Dict[str, Any]:
    """
    Returns:
      {"status":"ok","provider":{abbr,full_name,role}}
      {"status":"ambiguous","choices":[{abbr,full_name,role},...],"prompt": "..."}
      {"status":"not_found"}
    """
    q = _norm(query)
    db = SessionLocal()
    try:
        # 1) exact match on abbr/full_name/alias
        # abbr
        prov = db.execute(select(Provider).where(Provider.abbr.ilike(q))).scalar_one_or_none()
        if prov:
            return {"status":"ok","provider":{"abbr":prov.abbr,"full_name":prov.full_name,"role":prov.role}}

        # full name exact
        prov = db.execute(select(Provider).where(Provider.full_name.ilike(query))).scalar_one_or_none()
        if prov:
            return {"status":"ok","provider":{"abbr":prov.abbr,"full_name":prov.full_name,"role":prov.role}}

        # alias exact
        alias_matches = db.execute(select(ProviderAlias).where(ProviderAlias.normalized == q)).scalars().all()
        if len(alias_matches) == 1:
            p = db.get(Provider, alias_matches[0].provider_id)
            return {"status":"ok","provider":{"abbr":p.abbr,"full_name":p.full_name,"role":p.role}}
        if len(alias_matches) > 1:
            choices = [{"abbr":db.get(Provider,a.provider_id).abbr,
                        "full_name":db.get(Provider,a.provider_id).full_name,
                        "role":db.get(Provider,a.provider_id).role} for a in alias_matches]
            names = ", ".join(c["full_name"] for c in choices)
            return {"status":"ambiguous","choices":choices,"prompt":f"Did you mean {names}? Please specify."}

        # 2) ambiguity rules (e.g., 'dr. henslee')
        rule = db.execute(select(AmbiguityRule).where(AmbiguityRule.trigger == q)).scalar_one_or_none()
        if rule:
            abbrs = [s.strip() for s in rule.abbrs_csv.split(",")]
            provs = db.execute(select(Provider).where(Provider.abbr.in_(abbrs))).scalars().all()
            choices = [{"abbr":p.abbr,"full_name":p.full_name,"role":p.role} for p in provs]
            return {"status":"ambiguous","choices":choices,"prompt":rule.prompt}

        # 3) light fuzzy (substring on name or alias)
        like = f"%{query}%"
        candidates = db.execute(select(Provider).where(Provider.full_name.ilike(like))).scalars().all()
        alias_candidates = db.execute(select(ProviderAlias).where(ProviderAlias.alias.ilike(like))).scalars().all()
        for a in alias_candidates:
            p = db.get(Provider, a.provider_id)
            if p not in candidates:
                candidates.append(p)

        if len(candidates) == 1:
            p = candidates[0]
            return {"status":"ok","provider":{"abbr":p.abbr,"full_name":p.full_name,"role":p.role}}
        if len(candidates) > 1:
            choices = [{"abbr":p.abbr,"full_name":p.full_name,"role":p.role} for p in candidates]
            names = ", ".join(c["full_name"] for c in choices)
            return {"status":"ambiguous","choices":choices,"prompt":f"Did you mean {names}? Please specify."}

        return {"status":"not_found"}
    finally:
        db.close()