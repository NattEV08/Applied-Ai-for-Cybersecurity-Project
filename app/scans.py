"""CLI-only wrappers; do not execute source code found in the target repository."""
import shutil
import subprocess
from pathlib import Path

def run_trivy(target, output):
    exe=shutil.which('trivy')
    if not exe: raise RuntimeError('Trivy executable unavailable: install it and verify trivy --version')
    target=Path(target).resolve()
    if not target.is_dir(): raise ValueError('Scan target must be an existing directory')
    output=Path(output).resolve(); output.parent.mkdir(parents=True,exist_ok=True)
    cmd=[exe,'fs','--scanners','vuln','--format','json','--output',str(output),str(target)]
    result=subprocess.run(cmd,text=True,capture_output=True,timeout=300,check=False,shell=False)
    if result.returncode != 0 or not output.exists():
        raise RuntimeError(f'Trivy scan failed (exit {result.returncode}): {result.stderr[-1500:]}')
    return output

def run_bandit(target,output):
    exe=shutil.which('bandit')
    if not exe: raise RuntimeError('Bandit executable unavailable: pip install -r requirements.txt')
    target=Path(target).resolve()
    if not target.is_dir(): raise ValueError('Scan target must be an existing directory')
    output=Path(output).resolve(); output.parent.mkdir(parents=True,exist_ok=True)
    cmd=[exe,'-r',str(target),'-f','json','-o',str(output)]
    result=subprocess.run(cmd,text=True,capture_output=True,timeout=180,check=False,shell=False)
    # Bandit exits 1 if its scan identified issues. JSON output must still be valid.
    if result.returncode not in (0,1) or not output.exists():
        raise RuntimeError(f'Bandit scan failed (exit {result.returncode}): {result.stderr[-1500:]}')
    return output
