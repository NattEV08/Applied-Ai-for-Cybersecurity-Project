# Training-only SAST fixture: do not deploy or execute.
from pathlib import Path

def show_config():
    password = "test-only-hardcoded-password"  # Bandit B105 candidate
    return 'configured' if password else 'missing'
