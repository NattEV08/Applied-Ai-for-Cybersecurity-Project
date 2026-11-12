"""Translate Bandit and Trivy JSON into a shared, evidence-oriented interface."""
from pathlib import Path

SEVERITIES = {'UNKNOWN','LOW','MEDIUM','HIGH','CRITICAL'}

def _sev(value):
    value = str(value or 'UNKNOWN').upper()
    return value if value in SEVERITIES else 'UNKNOWN'

def normalize_trivy(document, asset_id):
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

def normalize_bandit(document, asset_id):
    records=[]
    for issue in document.get('results') or []:
        cwe = issue.get('issue_cwe') or {}
        cwe_id = f"CWE-{cwe['id']}" if cwe.get('id') is not None else None
        records.append({
            'scanner':'SAST-Bandit','asset_id':asset_id,
            'finding_id':str(issue.get('test_id') or 'B???'),
            'severity':_sev(issue.get('issue_severity')),
            'cve_id':None,'cwe_id':cwe_id,'cvss_score':None,
            'package':None,'installed_version':None,'fixed_version':None,
            'file_path':str(issue.get('filename') or '')+':'+str(issue.get('line_number') or ''),
            'description':str(issue.get('issue_text') or '')[:2000],
            'reference_url':issue.get('more_info'),
        })
    return records
