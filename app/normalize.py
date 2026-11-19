"""Translate Bandit and Trivy JSON into a shared, evidence-oriented interface."""
from collections import Counter
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
SEVERITIES = {'UNKNOWN','LOW','MEDIUM','HIGH','CRITICAL'}
SEVERITY_RANK = {'UNKNOWN': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
CONFIDENCE_RANK = {'UNKNOWN': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}

def _sev(value):
    value = str(value or 'UNKNOWN').upper()
    return value if value in SEVERITIES else 'UNKNOWN'

def _conf(value):
    value = str(value or 'UNKNOWN').upper()
    return value if value in CONFIDENCE_RANK else 'UNKNOWN'

def _clean_bandit_file_path(filename, line_number):
    raw_file = str(filename or '').strip()
    if raw_file:
        try:
            p = Path(raw_file)
            if p.is_absolute():
                raw_file = p.resolve().relative_to(BASE).as_posix()
            else:
                raw_file = raw_file.replace('\\', '/')
                if raw_file.startswith('./'):
                    raw_file = raw_file[2:]
        except Exception:
            raw_file = raw_file.replace('\\', '/')
    line_str = str(line_number if line_number is not None else '')
    return f"{raw_file}:{line_str}"

def normalize_trivy(document, asset_id):
    if not isinstance(document, dict):
        raise ValueError('Trivy report must be a JSON object')
    records = []
    for group in document.get('Results') or []:
        target = str(group.get('Target') or '')
        for v in group.get('Vulnerabilities') or []:
            score = None
            for vendor in ('nvd','redhat','ghsa'):
                candidate = (v.get('CVSS') or {}).get(vendor) or {}
                for key in ('V4Score','V3Score'):
                    raw = candidate.get(key)
                    if isinstance(raw,(int,float)) and 0 <= raw <= 10:
                        score = float(raw)
                        break
                if score is not None: break
            records.append({
                'scanner':'SCA-Trivy','asset_id':asset_id,
                'finding_id':str(v.get('VulnerabilityID') or 'UNKNOWN'),
                'severity':_sev(v.get('Severity')),
                'cve_id':str(v.get('VulnerabilityID')) if str(v.get('VulnerabilityID','')).startswith('CVE-') else None,
                'cwe_id':None,'cvss_score':score,
                'package':v.get('PkgName'),'installed_version':v.get('InstalledVersion'),
                'fixed_version':v.get('FixedVersion'), 'file_path':target,
                'description':str(v.get('Title') or v.get('Description') or '')[:2000],
                'reference_url':v.get('PrimaryURL'),
            })
    return records

def normalize_bandit(document, asset_id, min_severity=None, min_confidence=None):
    if not isinstance(document, dict):
        raise ValueError('Bandit report must be a JSON object')
    results = document.get('results')
    if results is not None and not isinstance(results, list):
        raise ValueError('Bandit report "results" field must be a list')
    min_sev_rank = SEVERITY_RANK.get(_sev(min_severity), 0) if min_severity else 0
    min_conf_rank = CONFIDENCE_RANK.get(_conf(min_confidence), 0) if min_confidence else 0

    records=[]
    for issue in results or []:
        if not isinstance(issue, dict):
            continue
        sev = _sev(issue.get('issue_severity'))
        conf = _conf(issue.get('issue_confidence'))
        if SEVERITY_RANK.get(sev, 0) < min_sev_rank:
            continue
        if CONFIDENCE_RANK.get(conf, 0) < min_conf_rank:
            continue
        cwe = issue.get('issue_cwe') if isinstance(issue.get('issue_cwe'), dict) else {}
        raw_cwe_id = cwe.get('id')
        cwe_id = f"CWE-{raw_cwe_id}" if raw_cwe_id is not None and str(raw_cwe_id).strip() != '' else None
        records.append({
            'scanner':'SAST-Bandit','asset_id':asset_id,
            'finding_id':str(issue.get('test_id') or 'B???'),
            'severity':sev,
            'cve_id':None,'cwe_id':cwe_id,'cvss_score':None,
            'package':None,'installed_version':None,'fixed_version':None,
            'file_path':_clean_bandit_file_path(issue.get('filename'), issue.get('line_number')),
            'description':str(issue.get('issue_text') or '')[:2000],
            'reference_url':issue.get('more_info'),
        })
    return records

def summarize_sast_findings(records, asset_id=None):
    """Programmatically summarize SAST findings for fast, grounded local LLM context."""
    sast_rows = [
        r for r in (records or [])
        if r.get('scanner') == 'SAST-Bandit' and (asset_id is None or r.get('asset_id') == asset_id)
    ]
    sev_counts = Counter(r.get('severity', 'UNKNOWN') for r in sast_rows)
    cwe_counts = Counter(r.get('cwe_id') or 'UNMAPPED-CWE' for r in sast_rows)
    target_label = asset_id or (sast_rows[0].get('asset_id') if sast_rows else 'target repository')
    if not sast_rows:
        summary_text = f"Asset {target_label} has 0 SAST findings from Bandit."
    else:
        sev_parts = [f"{sev_counts[s]} {s}" for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN') if sev_counts[s]]
        cwe_parts = [f"{cwe} ({count})" for cwe, count in cwe_counts.most_common(5)]
        summary_text = (
            f"Asset {target_label} has {len(sast_rows)} SAST finding(s) "
            f"[{', '.join(sev_parts)}] across CWEs: {', '.join(cwe_parts)}."
        )
    return {
        'asset_id': target_label,
        'total_findings': len(sast_rows),
        'severity_breakdown': dict(sev_counts),
        'cwe_breakdown': dict(cwe_counts),
        'summary_text': summary_text,
    }
