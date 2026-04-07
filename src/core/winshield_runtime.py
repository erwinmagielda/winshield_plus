import subprocess
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))

TRAINING_DIR = os.path.join(ROOT_DIR, "training")

PYTHON = sys.executable

pipeline = [
    "flatten.py",
    "enrich.py",
    "validate.py"
]

print("\n=== WinShield Runtime Processing ===\n")

for script in pipeline:

    script_path = os.path.join(TRAINING_DIR, script)

    print(f"Running {script}...")

    result = subprocess.run(
        [PYTHON, script_path, "--mode", "runtime"]
    )

    if result.returncode != 0:
        raise RuntimeError(f"{script} failed")

print("\nRuntime dataset ready.")