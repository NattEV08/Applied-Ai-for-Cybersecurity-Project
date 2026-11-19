"""CLI-only wrappers; do not execute source code found in the target repository."""
import json
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path

DEFAULT_BANDIT_EXCLUDES = ('.venv', 'venv', '.git', '__pycache__', 'node_modules', 'build', 'dist')

def _validate_target_dir(target):
    if target is None or not str(target).strip():
        raise ValueError('Scan target must be a non-empty directory path')
    raw = str(target).strip()
    if '\x00' in raw or raw.startswith('-'):
        raise ValueError('Scan target contains invalid characters or option prefix')
    resolved = Path(raw).resolve()
    if not resolved.exists() or not resolved.is_dir():
        raise ValueError('Scan target must be an existing directory')
    return resolved

def _find_bandit_exe():
    exe = shutil.which('bandit')
    if exe:
        return exe
    scripts_dir = Path(sys.executable).resolve().parent
    for candidate_name in ('bandit.exe', 'bandit'):
        candidate = scripts_dir / candidate_name
        if candidate.is_file():
            return str(candidate)
    return None

def run_trivy(target, output):
    exe=shutil.which('trivy')
    if not exe: raise RuntimeError('Trivy executable unavailable: install it and verify trivy --version')
    target=_validate_target_dir(target)
    output=Path(output).resolve(); output.parent.mkdir(parents=True,exist_ok=True)
    cmd=[exe,'fs','--scanners','vuln','--format','json','--output',str(output),str(target)]
    result=subprocess.run(cmd,text=True,capture_output=True,timeout=300,check=False,shell=False)  # nosec B603
    if result.returncode != 0 or not output.exists():
        raise RuntimeError(f'Trivy scan failed (exit {result.returncode}): {result.stderr[-1500:]}')
    return output

def run_bandit(target, output, exclude_dirs=DEFAULT_BANDIT_EXCLUDES):
    exe=_find_bandit_exe()
    if not exe: raise RuntimeError('Bandit executable unavailable: pip install -r requirements.txt')
    target=_validate_target_dir(target)
    output=Path(output).resolve(); output.parent.mkdir(parents=True,exist_ok=True)
    cmd=[exe,'-r',str(target),'-f','json','-o',str(output)]
    if exclude_dirs:
        excluded = [str(target / d) for d in exclude_dirs]
        cmd.extend(['-x', ','.join(excluded)])
    result=subprocess.run(cmd,text=True,capture_output=True,timeout=180,check=False,shell=False)  # nosec B603
    # Bandit exits 0 when no issues are found, 1 when issues are identified, and >=2 on error.
    if result.returncode not in (0,1) or not output.exists():
        raise RuntimeError(f'Bandit scan failed (exit {result.returncode}): {result.stderr[-1500:]}')
    try:
        payload = json.loads(output.read_text(encoding='utf8'))
    except Exception as exc:
        raise RuntimeError(f'Bandit produced invalid JSON output: {exc}') from exc
    if not isinstance(payload, dict) or 'results' not in payload:
        raise RuntimeError('Bandit JSON output missing expected "results" array')
    return output
