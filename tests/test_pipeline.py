import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from app.normalize import normalize_trivy, normalize_bandit, summarize_sast_findings
from app.db import initialize, ingest, fetch
from app.risk import add_priority
from app.scans import run_bandit, _find_bandit_exe

ROOT=Path(__file__).resolve().parent.parent
class PipelineTests(unittest.TestCase):
 def test_trivy_preserves_cve_and_cvss(self):
    r=normalize_trivy(json.loads((ROOT/'fixtures/trivy_sample.json').read_text()),'AST-ECOM')
    self.assertEqual(len(r),2)
    self.assertEqual(r[0]['cve_id'],'CVE-2099-00001')
    self.assertEqual(r[0]['cvss_score'],8.1)
    self.assertIsNone(r[1]['cvss_score'])
    self.assertIsNone(r[1]['fixed_version'])
 def test_bandit_preserves_cwe_without_fabricating_cvss(self):
    r=normalize_bandit(json.loads((ROOT/'fixtures/bandit_sample.json').read_text()),'AST-POS')
    self.assertEqual(r[0]['cwe_id'],'CWE-259')
    self.assertIsNone(r[0]['cve_id'])
    self.assertIsNone(r[0]['cvss_score'])
 def test_risk_distinguishes_cvss_from_priority(self):
    row={'cvss_score':None,'severity':'HIGH','exposure':'public','criticality':5,'data_sensitivity':5}
    scored=add_priority(row)
    self.assertIsNone(scored['cvss_score'])
    self.assertEqual(scored['score_basis'],'severity proxy; not CVSS')
 def test_fixture_database_ingestion(self):
    with tempfile.TemporaryDirectory() as d:
        db=Path(d)/'temp.db'; initialize(db)
        rows=normalize_trivy(json.loads((ROOT/'fixtures/trivy_sample.json').read_text()),'AST-ECOM')
        ingest(rows,db)
        ingest(rows,db)  # repeated scan should update, not duplicate
        saved=fetch(db)
        self.assertEqual(len(saved),2)
        self.assertEqual(saved[0]['stakeholder'],'E-commerce Product Owner')

 # --- Member 1 (SAST - Bandit) unit & evaluation tests ---
 def test_bandit_missing_cwe_and_unknown_severity(self):
    doc = {
        'results': [{
            'test_id': 'B999',
            'issue_severity': 'UNEXPECTED',
            'issue_confidence': 'HIGH',
            'issue_cwe': {},
            'issue_text': 'Synthetic unmapped CWE issue',
            'filename': 'fixtures/target-repo/app.py',
            'line_number': 10,
            'more_info': None,
        }]
    }
    rows = normalize_bandit(doc, 'AST-POS')
    self.assertEqual(len(rows), 1)
    self.assertIsNone(rows[0]['cwe_id'])
    self.assertEqual(rows[0]['severity'], 'UNKNOWN')
    self.assertIsNone(rows[0]['cve_id'])
    self.assertIsNone(rows[0]['cvss_score'])

 def test_bandit_empty_report_and_malformed_input(self):
    self.assertEqual(normalize_bandit({'results': [], 'errors': []}, 'AST-POS'), [])
    with self.assertRaises(ValueError):
        normalize_bandit(['not-a-dict'], 'AST-POS')
    with self.assertRaises(ValueError):
        normalize_bandit({'results': 'not-a-list'}, 'AST-POS')

 def test_bandit_path_normalization_strips_absolute_prefix(self):
    abs_file = str((ROOT / 'fixtures' / 'target-repo' / 'app.py').resolve())
    doc = {
        'results': [{
            'test_id': 'B105',
            'issue_severity': 'LOW',
            'issue_confidence': 'MEDIUM',
            'issue_cwe': {'id': 259},
            'issue_text': 'Hardcoded password',
            'filename': abs_file,
            'line_number': 4,
        }]
    }
    rows = normalize_bandit(doc, 'AST-POS')
    self.assertEqual(rows[0]['file_path'], 'fixtures/target-repo/app.py:4')

 def test_bandit_confidence_and_severity_filtering(self):
    doc = {
        'results': [
            {'test_id': 'B404', 'issue_severity': 'LOW', 'issue_confidence': 'HIGH', 'issue_cwe': {'id': 78}, 'filename': 'a.py', 'line_number': 1, 'issue_text': 'import subprocess'},
            {'test_id': 'B608', 'issue_severity': 'MEDIUM', 'issue_confidence': 'MEDIUM', 'issue_cwe': {'id': 89}, 'filename': 'a.py', 'line_number': 5, 'issue_text': 'sql injection'},
            {'test_id': 'B602', 'issue_severity': 'HIGH', 'issue_confidence': 'HIGH', 'issue_cwe': {'id': 78}, 'filename': 'a.py', 'line_number': 9, 'issue_text': 'shell=True'},
        ]
    }
    med_plus = normalize_bandit(doc, 'AST-POS', min_severity='MEDIUM')
    self.assertEqual([r['finding_id'] for r in med_plus], ['B608', 'B602'])
    high_conf_high_sev = normalize_bandit(doc, 'AST-POS', min_severity='HIGH', min_confidence='HIGH')
    self.assertEqual([r['finding_id'] for r in high_conf_high_sev], ['B602'])

 def test_sast_programmatic_llm_summary(self):
    rows = normalize_bandit(json.loads((ROOT/'fixtures/bandit_sample.json').read_text()), 'AST-POS')
    summary = summarize_sast_findings(rows, asset_id='AST-POS')
    self.assertEqual(summary['total_findings'], 1)
    self.assertEqual(summary['cwe_breakdown']['CWE-259'], 1)
    self.assertIn('AST-POS', summary['summary_text'])
    self.assertIn('CWE-259', summary['summary_text'])

 def test_run_bandit_rejects_invalid_targets(self):
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / 'out.json'
        with self.assertRaises(ValueError):
            run_bandit(Path(d) / 'does_not_exist', out)
        with self.assertRaises(ValueError):
            run_bandit('-r', out)
        file_target = Path(d) / 'some_file.py'
        file_target.write_text('x = 1\n', encoding='utf8')
        with self.assertRaises(ValueError):
            run_bandit(file_target, out)

 def test_run_bandit_handles_missing_binary_and_exit_codes(self):
    with tempfile.TemporaryDirectory() as d:
        target = Path(d)
        out = target / 'bandit.json'
        with patch('app.scans._find_bandit_exe', return_value=None):
            with self.assertRaises(RuntimeError):
                run_bandit(target, out)

        def fake_run_exit1(cmd, **kwargs):
            out.write_text('{"results": [], "errors": []}', encoding='utf8')
            return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='')

        with patch('app.scans._find_bandit_exe', return_value='bandit'), patch('app.scans.subprocess.run', side_effect=fake_run_exit1):
            res = run_bandit(target, out)
            self.assertEqual(res, out.resolve())

        def fake_run_exit2(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 2, stdout='', stderr='fatal scanner error')

        with patch('app.scans._find_bandit_exe', return_value='bandit'), patch('app.scans.subprocess.run', side_effect=fake_run_exit2):
            with self.assertRaises(RuntimeError):
                run_bandit(target, out)

        def fake_run_bad_json(cmd, **kwargs):
            out.write_text('{corrupted json', encoding='utf8')
            return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')

        with patch('app.scans._find_bandit_exe', return_value='bandit'), patch('app.scans.subprocess.run', side_effect=fake_run_bad_json):
            with self.assertRaises(RuntimeError):
                run_bandit(target, out)

 @unittest.skipUnless(_find_bandit_exe() is not None, 'Bandit CLI not installed in current environment')
 def test_live_bandit_scan_precision_and_self_scan(self):
    with tempfile.TemporaryDirectory() as d:
        # 1. Live scan on target-repo fixture: verify expected CWEs & inline # nosec suppression
        fixture_out = Path(d) / 'fixture_bandit.json'
        run_bandit(ROOT / 'fixtures' / 'target-repo', fixture_out)
        report = json.loads(fixture_out.read_text(encoding='utf8'))
        rows = normalize_bandit(report, 'AST-POS')
        found_cwes = {r['cwe_id'] for r in rows}
        found_tests = {r['finding_id'] for r in rows}
        self.assertTrue({'CWE-259', 'CWE-89', 'CWE-78', 'CWE-502', 'CWE-327'}.issubset(found_cwes))
        self.assertNotIn('B101', found_tests)  # suppressed via # nosec B101

        # 2. Dogfooding self-scan on application code (app/): must have 0 findings
        self_out = Path(d) / 'self_bandit.json'
        run_bandit(ROOT / 'app', self_out)
        self_report = json.loads(self_out.read_text(encoding='utf8'))
        self.assertEqual(normalize_bandit(self_report, 'AST-POS'), [])

if __name__=='__main__':unittest.main()
