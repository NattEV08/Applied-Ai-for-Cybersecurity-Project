# Member 1 — SAST (Bandit) Technical Runbook & Proposal Guide

## What You Own
Your feature performs **Static Application Security Testing (SAST)** of *authorized* Python source-code repositories using **PyCQA Bandit**. Your pipeline executes Bandit safely via `subprocess.run(..., shell=False)`, parses the raw Bandit JSON report (`results[]`), extracts **Common Weakness Enumeration (CWE)** identifiers, severity/confidence ratings, and repo-relative file/line locations, and normalizes them into the shared SQLite schema so Member 3 can join findings to retail business assets (`AST-ECOM`, `AST-POS`, `AST-TRAIN`) and generate grounded local Ollama remediation guidance.

**What you do NOT do:** You do not fabricate CVE IDs or CVSS scores for SAST findings (`cve_id = None`, `cvss_score = None`), execute untrusted target repository code, or expose arbitrary filesystem paths to web users.

---

### What You Should Explain in the Week 8 Proposal & Presentation
1. **SAST vs. SCA:** Bandit inspects **first-party Python AST (Abstract Syntax Tree) patterns** to identify coding weaknesses mapped to **CWEs** (e.g., `CWE-89` SQL Injection, `CWE-78` OS Command Injection, `CWE-259` Hardcoded Password). Trivy (Member 2) inspects **third-party dependency manifests** (`requirements.txt` / lockfiles) for published advisories (**CVEs** and vendor **CVSS** scores).
2. **Why SAST Never Invents CVSS:** CWEs describe weakness categories in custom source code rather than specific published package advisories with NVD CVSS vectors. Our normalizer sets `cvss_score = None` and `cve_id = None` for all Bandit findings; Member 3's deterministic risk engine explicitly labels SAST scoring as `severity proxy; not CVSS`.
3. **Safe CLI Execution & Exit-Code Handling:**
   - `run_bandit()` in `app/scans.py` resolves the `bandit` executable (from `PATH` or the active Python environment's `Scripts/` directory), validates that the target is an existing directory with no CLI option injection (`-`) or null bytes, and invokes Bandit with `shell=False` and `timeout=180`.
   - Bandit returns **exit code `0`** when 0 issues are found, **exit code `1`** when 1 or more issues are detected, and **exit code `>= 2`** on CLI/scanner failure. `run_bandit()` accepts `(0, 1)` and verifies that the output file is valid JSON containing a `"results"` list.
   - Non-source/environment directories (`.venv`, `venv`, `.git`, `__pycache__`, `node_modules`, `build`, `dist`) are automatically excluded via `-x` so scans remain fast (`< 2s`) and never scan third-party `site-packages`.
4. **Path Normalization & Data Privacy:**
   - `_clean_bandit_file_path()` in `app/normalize.py` strips absolute machine prefixes (e.g., `C:\Users\...\fixtures\target-repo\app.py`) into portable repo-relative POSIX paths (`fixtures/target-repo/app.py:4`). This prevents leaking local developer usernames into SQLite or LLM prompts and ensures SHA-256 deduplication fingerprints in `app/db.py` are identical across Windows and Linux.
5. **False-Positive Triage & Dogfooding (Self-Scan):**
   - Inline `# nosec BXXX` directives suppress audited non-issues (demonstrated on `B101` in `fixtures/target-repo/app.py` and `B404`/`B603` in `app/scans.py`).
   - `normalize_bandit()` supports `min_severity` and `min_confidence` thresholds to filter low-confidence noise.
   - Running Bandit against our own application (`bandit -r app project.py`) passes with **0 findings**.

---

## 1. Setup on Windows PowerShell

From the repository root (`Applied-Ai-for-Cybersecurity-Project`):

```powershell
# Activate existing virtual environment (or create one with: py -3 -m venv venv)
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
bandit --version
python -m unittest discover -s tests -v
```

If PowerShell blocks `Activate.ps1`, invoke `.\venv\Scripts\python.exe` and `.\venv\Scripts\bandit.exe` directly without relaxing system-wide execution policies.

---

## 2. Standalone Bandit CLI Scan & Self-Scan Verification

### A. Scan the Intentional Vulnerable Target Fixture (`fixtures/target-repo`)
**Never execute or deploy `fixtures/target-repo/app.py`; Bandit parses its AST statically without importing or executing it.**

```powershell
New-Item -ItemType Directory -Force reports | Out-Null
.\venv\Scripts\bandit.exe -r fixtures/target-repo -f json -o reports/bandit_live.json
```

Expected: Bandit exits with code `1` (because issues were found) and writes `reports/bandit_live.json` containing 7 findings across 5 CWEs (`CWE-78`, `CWE-327`, `CWE-89`, `CWE-502`, `CWE-259`), while skipping the `# nosec B101` line.

### B. Dogfooding Self-Scan on Our Own Application Code (`app/` and `project.py`)
```powershell
.\venv\Scripts\bandit.exe -r app project.py
```
Expected: `No issues identified.` (Exit code `0`).

---

## 3. Automated Scan → Normalize → SQLite → Summary

```powershell
.\venv\Scripts\python.exe project.py init
.\venv\Scripts\python.exe project.py ingest-samples
.\venv\Scripts\python.exe project.py scan-sast --target fixtures/target-repo --asset AST-POS
.\venv\Scripts\python.exe project.py summary
```

Expected `summary` output:
```text
AST-ECOM   SCA-Trivy    CVE-2099-00001      Critical 8.86 CVSS=8.1   owner=E-commerce Product Owner
AST-POS    SAST-Bandit  B602                High      7.8 CVSS=None  owner=POS Operations Manager
AST-POS    SAST-Bandit  B324                High      7.8 CVSS=None  owner=POS Operations Manager
AST-ECOM   SCA-Trivy    CVE-2099-00002      High      7.0 CVSS=None  owner=E-commerce Product Owner
AST-POS    SAST-Bandit  B608                High      6.3 CVSS=None  owner=POS Operations Manager
AST-POS    SAST-Bandit  B301                High      6.3 CVSS=None  owner=POS Operations Manager
AST-POS    SAST-Bandit  B105                Medium    4.8 CVSS=None  owner=POS Operations Manager
AST-POS    SAST-Bandit  B403                Medium    4.8 CVSS=None  owner=POS Operations Manager
AST-POS    SAST-Bandit  B404                Medium    4.8 CVSS=None  owner=POS Operations Manager
```

---

## 4. JSON Field Mapping Contract (Bandit → Shared SQLite Schema)

| Bandit JSON Field (`results[]`) | Shared Schema Field | Description & Contract Rule |
|---|---|---|
| *(Constant)* | `scanner` | Always `'SAST-Bandit'` |
| *(CLI `--asset` argument)* | `asset_id` | Explicit business asset (`'AST-ECOM'`, `'AST-POS'`, `'AST-TRAIN'`) |
| `test_id` | `finding_id` | Bandit rule ID (e.g., `'B105'`, `'B608'`, `'B602'`, `'B301'`, `'B324'`) |
| `issue_severity` | `severity` | Normalized to `'LOW'`, `'MEDIUM'`, `'HIGH'`, `'CRITICAL'`, or `'UNKNOWN'` |
| `issue_cwe.id` | `cwe_id` | Formatted as `'CWE-<id>'` (e.g., `'CWE-89'`) or `None` if absent |
| *(Not applicable to SAST)* | `cve_id` | Always `None` (never fabricated) |
| *(Not applicable to SAST)* | `cvss_score` | Always `None` (never fabricated) |
| *(Not applicable to SAST)* | `package`, `installed_version`, `fixed_version` | Always `None` |
| `filename` + `line_number` | `file_path` | Repo-relative POSIX path + line (`'fixtures/target-repo/app.py:4'`) |
| `issue_text` | `description` | Bandit finding description (truncated to `<= 2000` chars) |
| `more_info` | `reference_url` | Official PyCQA Bandit plugin documentation URL |

---

## 5. Member 1 Test Matrix & Measurable Evaluation Metrics (`tests/test_pipeline.py`)

| Test Case | Input / Scenario | Expected Result | Status |
|---|---|---|---|
| **Standard CWE extraction** | `fixtures/bandit_sample.json` (`B105`) | `cwe_id='CWE-259'`, `cve_id=None`, `cvss_score=None` | Passing |
| **Missing CWE & unknown severity** | `issue_cwe={}`, `issue_severity='UNEXPECTED'` | `cwe_id=None`, `severity='UNKNOWN'`, no crash | Passing |
| **Empty & malformed reports** | `{"results": []}` vs non-dict/invalid JSON | `[]` for empty; raises explicit `ValueError` for invalid structure | Passing |
| **Path privacy normalization** | Absolute Windows path under repo root | Stripped to relative POSIX `'fixtures/target-repo/app.py:4'` | Passing |
| **False-positive filtering** | `min_severity='MEDIUM'`, `min_confidence='HIGH'` | Filters out `LOW` import warnings (`B403`/`B404`), keeps high-priority CWEs | Passing |
| **Programmatic LLM summary** | `summarize_sast_findings(records, 'AST-POS')` | Aggregates counts by severity & CWE into concise text for Ollama | Passing |
| **Target path validation** | Missing dir, file path, or `-r` flag injection | Raises `ValueError` before `subprocess.run` is called | Passing |
| **Subprocess exit codes & binary check** | Exit `0`, `1`, `2`, missing binary, corrupt JSON | `0` & `1` succeed; `2`, missing binary, or corrupt JSON raise `RuntimeError` | Passing |
| **Duplicate scan idempotency** | Ingesting same Bandit report twice | SQLite `ON CONFLICT(fingerprint) DO UPDATE` prevents duplicate rows | Passing |
| **Live fixture precision & self-scan** | Live Bandit scan on `fixtures/target-repo` & `app/` | Detects all 5 seeded CWEs (`100%` recall), honors `# nosec B101`, `0` issues in `app/` | Passing |

---

## 6. Defense-in-Depth Controls Owned by Member 1

| Architectural Layer | Threat Addressed | Control Implemented in Code | Verification Test |
|---|---|---|---|
| **Application Layer** | Command / argument injection via scan target; arbitrary path scanning from web UI | Scan trigger is CLI-only (`project.py`) with strict `--asset` allowlist; `_validate_target_dir()` rejects option prefixes (`-`), null bytes, and non-directories; `subprocess.run(..., shell=False)` uses argument vectors. | `test_run_bandit_rejects_invalid_targets` |
| **Data & Storage Layer** | Local path disclosure (`C:\Users\<username>\...`); SQL injection in finding ingestion; duplicate row inflation | `_clean_bandit_file_path()` strips host-specific absolute paths; `app/db.py` uses static parameterized SQL (`UPSERT_FINDING_SQL`) with SHA-256 identity fingerprinting and auto-closing SQLite connections. | `test_bandit_path_normalization_strips_absolute_prefix`, `test_fixture_database_ingestion` |
| **System & Network Layer** | Untrusted code execution during scanning; resource exhaustion (`venv` scanning / hangs) | Bandit performs static AST parsing without executing target Python code; `run_bandit()` enforces `timeout=180` and excludes `.venv`, `venv`, `.git`, `node_modules`. | `test_live_bandit_scan_precision_and_self_scan` |

---

## 7. Suggested 5-Minute Presentation Script (Member 1 — SAST Lead)

- **0:00–0:45 — Role & Operational Context (Northstar Retail):**
  "Hi everyone, I'm Marcus, Member 1 and SAST Lead. In our Scenario B architecture for Northstar Retail, while Member 2 scans third-party libraries with Trivy, I own Static Application Security Testing for first-party Python code across our POS Management (`AST-POS`) and E-commerce (`AST-ECOM`) repositories using PyCQA Bandit."
- **0:45–1:45 — Safe Subprocess Wrapper & Defense-in-Depth (`app/scans.py`):**
  "Because scanning untrusted or unreviewed code carries system risks, `run_bandit()` never executes target code—Bandit parses the Python Abstract Syntax Tree statically. My wrapper validates that the target is an authorized local directory, blocks CLI flag injection, excludes virtual environments like `venv` so scans finish in under 2 seconds, and runs `subprocess.run` with `shell=False` and a 180-second timeout. Crucially, Bandit exits with code `1` whenever vulnerabilities are found, so my wrapper accepts exit codes `0` and `1` while raising a `RuntimeError` on exit code `2+` or malformed JSON."
- **1:45–2:45 — Evidence Normalization & CWE vs. CVE Contract (`app/normalize.py`):**
  "Bandit outputs `results[]` containing rule IDs (`B602`, `B608`, `B324`, `B301`, `B105`), severities, and MITRE CWE mappings. My normalizer extracts `CWE-78` (OS Command Injection), `CWE-89` (SQL Injection), `CWE-327` (Weak Hashing), `CWE-502` (Unsafe Deserialization), and `CWE-259` (Hardcoded Passwords). Because SAST detects source code weaknesses rather than published package advisories, we never fabricate `cve_id` or `cvss_score`—both are strictly `None`, and Member 3's risk engine scores them using our documented severity proxy. I also strip absolute local file paths into portable repo-relative paths (`fixtures/target-repo/app.py:4`) so developer usernames aren't leaked into SQLite or LLM prompts."
- **2:45–3:45 — False-Positive Triage, LLM Summarization & Dogfooding:**
  "To handle SAST noise, I implemented severity and confidence threshold filtering in `normalize_bandit()`, demonstrated inline `# nosec` suppression for audited code, and built `summarize_sast_findings()` to give Member 3's local Ollama model a concise CWE/severity breakdown instead of dumping raw JSON. We also dogfood Bandit on our own `app/` codebase, achieving 0 findings after refactoring dynamic SQL in `app/db.py` into a static parameterized statement."
- **3:45–5:00 — Live Demo & Measurable Evaluation Results:**
  "In our test suite (`python -m unittest discover -s tests -v`), all 12 unit and integration tests pass in ~2 seconds, demonstrating 100% extraction precision across all 5 seeded CWEs in `fixtures/target-repo`, deterministic SQLite upsert deduplication, and full resilience against missing binaries, bad targets, and corrupted JSON."
