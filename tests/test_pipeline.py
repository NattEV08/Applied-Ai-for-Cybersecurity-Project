import json
import tempfile
import unittest
from pathlib import Path
from app.normalize import normalize_trivy,normalize_bandit
from app.db import initialize,ingest,fetch
from app.risk import add_priority

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
if __name__=='__main__':unittest.main()
