# Week 4–8 plan: short tasks and acceptance criteria

## Week 4 — Interface freeze / reproducible proof
- M1: Run Bandit on synthetic target; document JSON `results`, CWE mapping.
- M2: Install Trivy; run `trivy fs --scanners vuln --format json --output reports/trivy_live.json fixtures/target-repo`; document `Results[].Vulnerabilities[]`, CVEs, package, versions, CVSS limitations.
- M3: Create seeded SQLite schema + deterministic priority function; verify SAST does not get invented CVSS.
- M4: Create localhost read-only dashboard; draft threat model for three layers.
- Joint: agree normalized finding schema and one sample end-to-end screenshot.

## Week 5 — Wrappers / quality
- M1: handle Bandit exit code 1, parser errors, no arbitrary web-supplied scan target.
- M2: build Trivy wrapper, handle missing tool/DB/lockfiles, add parser fixture tests.
- M3: Ollama structured output + context retrieval; no hallucinated CVE/CVSS.
- M4: dashboard source labels, error states, access-control proposal.

## Week 6 — Integration / evaluation plan
- M1 + M2: fixture and authorized test-repo coverage, false-positive triage.
- M3: repeated score computation; human approval loop for remediation.
- M4: controls with test cases: application, storage, OS/network.
- Joint: demo scan → DB → scoring → optional AI explanation → dashboard.

## Week 7 — Proposal polishing
- Architecture diagram, user flow, stack, team allocation, testing metrics, limitations.
- Individual slides show interfaces, expected inputs, outputs, errors and security controls.

## Week 8 — Proposal presentation
- Team leader submits the single deck by Sunday 23:59 in presentation week.
- 5-min leader intro; 5 min each; 5-min Q&A. Rehearse limitations of local inference and scoring.

## Week 13 — Progress review
Working prototype code, screen layouts and user flow. Proof that all modules integrate on local hardware.

## Week 16 — Technical review
>=80% feature completion; latency/error/robustness tests; three-layer controls demonstrated.

## Week 18 — Final
Integrated demo, individual technical demo, final group report and peer appraisal.
