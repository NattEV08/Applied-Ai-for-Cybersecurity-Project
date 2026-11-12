"""Deterministic internal priority heuristic, not a CVSS score."""
SEVERITY_PROXY={'CRITICAL':9.5,'HIGH':7.5,'MEDIUM':5.0,'LOW':2.5,'UNKNOWN':0.0}
EXPOSURE={'public':10.0,'internal':6.0,'isolated':2.0}

def add_priority(finding):
    v=dict(finding)
    cvss=v.get('cvss_score')
    technical = float(cvss) if cvss is not None else SEVERITY_PROXY.get(v.get('severity'),0.0)
    c=float(v['criticality'])/5*10
    s=float(v['data_sensitivity'])/5*10
    exposure=EXPOSURE.get(v['exposure'],0.0)
    score=round(0.60*technical+0.20*c+0.15*exposure+0.05*s,2)
    label='Critical' if score >= 8 else 'High' if score >= 6 else 'Medium' if score >= 4 else 'Low'
    v.update(priority_score=score, priority_label=label,
             score_basis='published CVSS' if cvss is not None else 'severity proxy; not CVSS')
    return v
