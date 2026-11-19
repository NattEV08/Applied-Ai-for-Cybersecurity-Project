# Training-only SAST fixture: do not deploy or execute.
from pathlib import Path
def show_config():
    password = "test-only-hardcoded-password"  # Bandit B105 candidate (CWE-259)
    return 'configured' if password else 'missing'

import hashlib
import pickle
import subprocess

def lookup_pos_transaction(cursor, receipt_id):
    # Synthetic B608 candidate: SQL injection via formatted query string (CWE-89)
    query = f"SELECT * FROM pos_receipts WHERE receipt_id = '{receipt_id}'"
    return cursor.execute(query)

def run_terminal_diagnostic(terminal_host):
    # Synthetic B602 candidate: subprocess call with shell=True (CWE-78)
    cmd = f"ping -n 1 {terminal_host}"
    return subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def deserialize_cart_state(payload_bytes):
    # Synthetic B301 candidate: unsafe pickle deserialization of untrusted input (CWE-502)
    return pickle.loads(payload_bytes)

def compute_voucher_digest(voucher_code):
    # Synthetic B324 candidate: weak MD5 hash used in security context (CWE-327)
    return hashlib.md5(voucher_code.encode('utf-8')).hexdigest()

def verify_non_security_invariant(batch_items):
    # Example of triaged false positive suppressed via inline # nosec directive
    assert isinstance(batch_items, list)  # nosec B101
    return len(batch_items)
