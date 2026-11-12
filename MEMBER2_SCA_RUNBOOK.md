# Member 2 — SCA (Trivy) technical runbook

## What you own
Your feature performs **Software Composition Analysis** of *authorized* source-code repositories, focusing on third-party dependency manifests and lockfiles. Your work turns Trivy JSON evidence into a stable data format that Member 3 can connect to retail business assets. **You are not training a vulnerability prediction model**, conducting live network scanning, or manufacturing CVSS/CVE data.

### What you should be able to explain in the Week 8 proposal
1. SAST versus SCA: Bandit checks Python coding patterns (often CWE); Trivy checks libraries/dependencies for known vulnerabilities (often CVE or another advisory ID).
2. Why lockfiles/pinned versions matter, and why an unpinned requirement can be underspecified.
3. How the CLI is invoked safely (`subprocess.run` argument vector, no shell), and how you handle failures.
4. How a Trivy report is parsed from `Results[] → Vulnerabilities[]` without losing source evidence.
5. How the scan record becomes associated with **one specific authorized repository/asset**.
6. How security is layered: authorized target only, no code execution, no exposed scan API, no secrets committed, loopback-only local AI.

## 1. Setup on Windows PowerShell
Install Python 3.11+ and Git. Clone the existing GitHub repository (replace placeholder with your team's real link):

```powershell
git clone https://github.com/TEAM/REPO.git
cd REPO
git switch -c feature/member2-sca-trivy
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Install **Trivy** separately from https://www.trivy.dev/docs/latest/getting-started/installation/ . On Windows download the official release ZIP, unzip `trivy.exe`, and add its folder to the User `PATH`. Open a fresh terminal and verify:

```powershell
trivy --version
```

If PowerShell blocks your venv activation, use `.venv\Scripts\python.exe` directly rather than relaxing machine-wide execution policies.

## 2. First standalone scan
The fixture contains deliberately outdated dependency entries. **Never install these packages; only scan the text files**.

```powershell
New-Item -ItemType Directory -Force reports | Out-Null
trivy fs --scanners vuln --format json --output reports/trivy_live.json fixtures/target-repo
```

Expected: JSON with `Results` containing zero or more `Vulnerabilities`; exact numbers, severity and IDs **depend on your latest Trivy advisory DB**. It is not correct to claim a certain result or CVE will always appear. Trivy can need network access to fetch its vulnerability database; once cached, report processing and Ollama inference can be local. For a strict offline demo, use the bundled synthetic report **and explicitly label it synthetic**.

### Kali / Debian installation
Use Trivy's official signed apt repository steps at https://www.trivy.dev/docs/latest/getting-started/installation/ rather than blindly running an arbitrary script. Then:

```bash
trivy --version
mkdir -p reports
trivy fs --scanners vuln --format json --output reports/trivy_live.json fixtures/target-repo
```

## 3. Automated scan → parse → SQLite

```powershell
python project.py init
python project.py scan-sca --target fixtures/target-repo --asset AST-ECOM
python project.py summary
```

The wrapper in `app/scans.py` executes Trivy with `shell=False`, validates the target is a directory, sets a timeout, checks the return code and verifies the JSON report exists. The parser in `app/normalize.py` extracts vulnerability entries. `app/db.py` maps each finding to `AST-ECOM` via the explicitly supplied asset ID and joins the stored asset's stakeholder/criticality.

For testing before installing Trivy:

```powershell
python project.py init
python project.py ingest-samples
python project.py summary
python -m unittest discover -s tests -v
```

**Do not confuse synthetic CVE-2099-* fixture identifiers with genuine public CVEs.**

## 4. JSON fields you should recognize

| Trivy field | Shared field | What it means |
|---|---|---|
| `Results[].Target` | `file_path` | Manifest/lockfile reported by scanner |
| `Vulnerabilities[].VulnerabilityID` | `finding_id` and `cve_id` only if CVE | A published advisory identifier, if present |
| `PkgName` | `package` | Vulnerable dependency |
| `InstalledVersion` | `installed_version` | Detected version, if present |
| `FixedVersion` | `fixed_version` | Known fix version, if published |
| `Severity` | `severity` | Scanner/vendor severity |
| `CVSS` | `cvss_score` | A source-provided numeric score, if available |
| `PrimaryURL` | `reference_url` | Evidence link for human verification |

Use `None`/`null` for missing data. A source CVSS score is **not** your locally calculated business-priority score. Preserve full scanner output in a local report for traceability; do not commit confidential reports.

## 5. Tests you should own

| Case | Input | Expected behavior |
|---|---|---|
| Standard finding | Fixture with package, CVE, CVSS and fixed version | All evidence retained, correct asset |
| Missing CVSS | Valid advisory with no CVSS object | `cvss_score = null`, no fabricated number |
| Missing fix | Valid advisory without `FixedVersion` | `fixed_version = null`, recommend investigation |
| Alternative ID | GHSA-style advisory | `finding_id` retained; `cve_id = null` |
| Empty report | No vulnerabilities | 0 findings, no crash |
| Missing Trivy | No binary in PATH | Clear installation error |
| Bad target | Missing directory | Reject before subprocess |
| Malformed JSON | Invalid report | Explicit parser failure; no false success |
| Duplicate scan | Same input twice | Upsert with no duplicate row |
| Security | Paths supplied only by a human CLI user | No remote arbitrary-path scan endpoint |

## 6. Week 4 deliverables to show your teammates
- `app/scans.py`: SCA wrapper that executes Trivy and returns the report path.
- `app/normalize.py`: Trivy JSON parser with null-safe field extraction.
- `tests/test_pipeline.py`: meaningful SCA tests that do not require internet.
- Example real Trivy report **on an approved, non-sensitive test repository**, stored locally, with the Trivy version and scan date recorded.
- One screenshot of `python project.py summary` proving your entries join the correct asset and stakeholder.
- Pull request with at least one peer reviewer and passing CI unit tests.

## 7. Working with the team
Merge the **normalized field contract first**. Member 1 can use the same schema for Bandit output, Member 3 can ingest both sources without coding against raw JSON, and Member 4 can design the dashboard against stable API fields. Avoid parallel edits to `project.py` or `app/db.py` without discussing interface changes. Create a short ADR (architecture decision record) for why Bandit and Trivy were selected.

## 8. Suggested 5-minute technical presentation
- 0:00–0:40 — Why software composition analysis matters to the retail scenario.
- 0:40–1:35 — Input files, pinned packages, how Trivy looks up known advisories.
- 1:35–2:35 — Command demonstration and raw JSON field extraction.
- 2:35–3:30 — Normalized interface and asset/stakeholder mapping.
- 3:30–4:30 — Edge cases: absent CVSS, transitive dependencies, missing fixes and errors.
- 4:30–5:00 — What you plan to deliver and how you will demonstrate security/effectiveness.

## Official source references
- Trivy filesystem scanning: https://www.trivy.dev/docs/latest/target/filesystem/
- Trivy Python-language package coverage: https://www.trivy.dev/docs/latest/guide/coverage/language/python/
- Trivy reporting formats: https://www.trivy.dev/docs/latest/guide/configuration/reporting/
- Trivy installation: https://www.trivy.dev/docs/latest/getting-started/installation/
