"""Local SQLite PoC storage. Not hardened enough for real company data."""
from pathlib import Path
import sqlite3
import hashlib
import json

BASE = Path(__file__).resolve().parent.parent
DEFAULT_DB = BASE/'data'/'project.db'

ASSETS = [
 ('AST-ECOM','E-commerce API','Digital Commerce','E-commerce Product Owner','public',5,5),
 ('AST-POS','POS manager','Retail Operations','POS Operations Manager','internal',5,4),
 ('AST-TRAIN','Employee training app','HR Learning','Training Coordinator','isolated',1,1),
]
SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
 asset_id TEXT PRIMARY KEY, name TEXT NOT NULL, business_unit TEXT NOT NULL,
 stakeholder TEXT NOT NULL, exposure TEXT NOT NULL CHECK (exposure IN ('public','internal','isolated')),
 criticality INTEGER NOT NULL CHECK (criticality BETWEEN 1 AND 5),
 data_sensitivity INTEGER NOT NULL CHECK (data_sensitivity BETWEEN 1 AND 5)
);
CREATE TABLE IF NOT EXISTS findings (
 id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT NOT NULL REFERENCES assets(asset_id),
 scanner TEXT NOT NULL, finding_id TEXT NOT NULL, severity TEXT NOT NULL,
 cve_id TEXT, cwe_id TEXT, cvss_score REAL, package TEXT,
 installed_version TEXT, fixed_version TEXT, file_path TEXT,
 description TEXT, reference_url TEXT,
 fingerprint TEXT NOT NULL UNIQUE
);
"""
FIELDS=('asset_id','scanner','finding_id','severity','cve_id','cwe_id','cvss_score','package','installed_version','fixed_version','file_path','description','reference_url')

def connect(db_path=DEFAULT_DB):
    db_path=Path(db_path)
    db_path.parent.mkdir(parents=True,exist_ok=True)
    conn=sqlite3.connect(db_path)
    conn.row_factory=sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

def initialize(db_path=DEFAULT_DB):
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)
        conn.executemany('INSERT OR IGNORE INTO assets VALUES (?,?,?,?,?,?,?)',ASSETS)

def ingest(items,db_path=DEFAULT_DB):
    columns=('fingerprint',)+FIELDS
    cols=', '.join(columns)
    placeholders=', '.join('?' for _ in columns)
    with connect(db_path) as conn:
        for item in items:
            identity=[item.get(k) for k in ('asset_id','scanner','finding_id','package','installed_version','file_path')]
            fingerprint=hashlib.sha256(json.dumps(identity,ensure_ascii=False).encode('utf8')).hexdigest()
            values=(fingerprint,)+tuple(item.get(field) for field in FIELDS)
            conn.execute(f'INSERT INTO findings ({cols}) VALUES ({placeholders}) ON CONFLICT(fingerprint) DO UPDATE SET severity=excluded.severity,cvss_score=excluded.cvss_score,fixed_version=excluded.fixed_version,description=excluded.description,reference_url=excluded.reference_url',values)
    return len(items)

def fetch(db_path=DEFAULT_DB):
    with connect(db_path) as conn:
        return [dict(x) for x in conn.execute("""
          SELECT f.*, a.name AS asset_name, a.business_unit, a.stakeholder,
           a.exposure, a.criticality, a.data_sensitivity
          FROM findings f JOIN assets a USING(asset_id)
          ORDER BY f.id
        """)]

def find_one(finding_id,db_path=DEFAULT_DB):
    with connect(db_path) as conn:
        row=conn.execute("""SELECT f.*,a.name AS asset_name,a.business_unit,a.stakeholder,
            a.exposure,a.criticality,a.data_sensitivity
            FROM findings f JOIN assets a USING(asset_id) WHERE f.id=?""",(finding_id,)).fetchone()
        return dict(row) if row else None
