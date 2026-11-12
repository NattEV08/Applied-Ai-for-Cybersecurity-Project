# IT2527 Week 4 starter — local AI vulnerability remediation

**Status:** teaching scaffold; not a production security scanner or enterprise-ready application.
**Ownership:** Member 1 = SAST (Bandit); Member 2 = SCA (Trivy); Member 3 = SQLite, risk and Ollama; Member 4 = Flask UI + security coordinator. All members implement defense in depth.

## Quickstart (Windows PowerShell)
1. Clone your existing team repository and copy the **contents** of this folder into it on a new branch. Review clashes with existing code; do not replace files blindly.
2. From the repository root:

```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python project.py init
python project.py ingest-samples
python project.py summary
python -m app.web
```

Open http://127.0.0.1:5000. The UI shows sample findings without needing Ollama. Sample Trivy CVE IDs in this scaffold are **synthetic, not real CVEs**.

## Member 2 / Trivy first live scan
Trivy is an **external executable** and is **not installed by pip**. Follow the official Trivy installation instructions; on Windows use the official release zip and add `trivy.exe` to PATH. On Kali use the official Debian repository instructions. Test using `trivy --version`.

```powershell
trivy fs --scanners vuln --format json --output reports\trivy_live.json fixtures\target-repo
python project.py scan-sca --target fixtures/target-repo --asset AST-ECOM
python project.py summary
```

The scan downloads/updates its vulnerability database unless cached. This is a **local scanner**, but initial DB updates can use the internet; do not claim the entire toolchain is air-gapped. The Ollama **AI inference** is local.

For a real approved repository: `python project.py scan-sca --target PATH_TO_AUTHORIZED_REPO --asset AST-ECOM`. Avoid executing untrusted repository code. Do not automatically install intentionally vulnerable dependencies in fixtures.

**Trivy caveats:** `requirements.txt` is best when dependencies are pinned with `==`, and may not include transitive dependencies; use lock files for stronger coverage. Findings depend on the local Trivy DB, package metadata and scan date. A successful scan may return 0 findings.

## Optional local Ollama
Install Ollama, run `ollama pull llama3.2:3b` (change `OLLAMA_MODEL` as appropriate), and ensure local server at `http://127.0.0.1:11434`. Model can vary with device. With Flask running, POST `/api/analyze/<finding_id>` to request AI recommendations; this is an optional model-backed step and will report an error clearly when Ollama is unavailable. Human review required for recommended remediations.

## Interface and design contracts
- SAST/SCA JSON inputs normalize into records with `scanner`, `finding_id`, `asset_id`, `severity`, `cwe_id`, `cve_id`, `cvss_score`, `package`, `installed_version`, `fixed_version`, `file_path`, `description`.
- SAST normally provides a CWE and **does not have a CVSS/CVE**. Never fabricate one.
- SCA normally provides known CVEs and sometimes CVSS/FixVersion; values can be absent.
- Asset mapping is an **explicit assignment** at ingestion, not inferred from a hostname appearing in code.
- Risk score is deterministic and separately labeled, **not a CVSS score**. An ordinal severity proxy is used only for score computation when CVSS is absent.
- The AI never decides the CVE, CWE, CVSS, asset owner or deterministic priority. It drafts narrative guidance only.

## Important guardrails
- Flask binds 127.0.0.1, debug off. No internet-facing service, no real organization source code, secrets, credentials or personal information.
- Only manually authorized paths may be passed to scanner CLI. No browser feature accepts an arbitrary local path. `subprocess.run()` uses argument arrays, never `shell=True`.
- `reports/`, `.env` and SQLite DB files are gitignored. For production, access controls and encryption are still REQUIRED; they are **not implemented** in this Week 4 baseline.
- No automatic fixes, installations, code execution or pull requests generated from LLM output.
- Sample scanning fixtures intentionally contain weaknesses. Never deploy or run the sample target as a service.

## Week 4 GitHub hand-off
Branch `feature/member2-sca-trivy` → PR with Trivy CLI evidence + JSON parser tests. Member 1 gets `feature/member1-sast`, Member 3 gets `feature/member3-ai-risk-db`, Member 4 gets `feature/member4-ui-security`. Keep a small common schema PR merged first. Require peer review and CI checks on `main` where available.

## Research
- https://www.trivy.dev/docs/latest/target/filesystem/
- https://www.trivy.dev/docs/latest/guide/coverage/language/python/
- https://www.trivy.dev/docs/latest/guide/configuration/reporting/
- https://bandit.readthedocs.io/en/latest/man/bandit.html
- https://github.com/ollama/ollama/blob/main/docs/capabilities/structured-outputs.mdx
- https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches
