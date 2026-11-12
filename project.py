"""Portable CLI entrypoint. All scanning is explicit and locally initiated."""
import argparse
import json
from pathlib import Path
from app.db import initialize,ingest,fetch
from app.normalize import normalize_bandit,normalize_trivy
from app.scans import run_trivy,run_bandit
from app.risk import add_priority

BASE=Path(__file__).resolve().parent

def load(path):
    return json.loads(Path(path).read_text(encoding='utf8'))

def main():
    parser=argparse.ArgumentParser(description='IT2527 baseline: CLI SAST, SCA, SQLite, risk')
    sub=parser.add_subparsers(dest='action',required=True)
    for action in ('init','ingest-samples','summary'):
        sub.add_parser(action)
    for action in ('scan-sca','scan-sast'):
        cmd=sub.add_parser(action)
        cmd.add_argument('--target',required=True,help='Authorized local source repository path')
        cmd.add_argument('--asset',required=True,choices=['AST-ECOM','AST-POS','AST-TRAIN'])
    args=parser.parse_args(); initialize()
    if args.action=='init': print('Database schema and three simulated business assets initialized.'); return
    if args.action=='ingest-samples':
        records=normalize_trivy(load(BASE/'fixtures'/'trivy_sample.json'),'AST-ECOM')
        records+=normalize_bandit(load(BASE/'fixtures'/'bandit_sample.json'),'AST-POS')
        print(f'Imported {ingest(records)} clearly synthetic sample finding(s).'); return
    if args.action in ('scan-sca','scan-sast'):
        output=BASE/'reports'/('trivy_live.json' if args.action=='scan-sca' else 'bandit_live.json')
        filename=run_trivy(args.target,output) if args.action=='scan-sca' else run_bandit(args.target,output)
        report=load(filename)
        records=normalize_trivy(report,args.asset) if args.action=='scan-sca' else normalize_bandit(report,args.asset)
        print(f'Scan saved to {filename}. Normalized {len(records)} findings, inserted {ingest(records)}.')
        return
    for f in sorted((add_priority(x) for x in fetch()),key=lambda r:r['priority_score'],reverse=True):
        print(f"{f['asset_id']:10} {f['scanner']:12} {f['finding_id']:19} "
              f"{f['priority_label']:8} {f['priority_score']:>4} "
              f"CVSS={f['cvss_score']!s:5} owner={f['stakeholder']}")

if __name__=='__main__':main()
