import subprocess
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

scripts = [
    "flatten.py",
    "enrich.py",
    "label.py",
    "validate.py",
    "preprocess.py"
]

for script in scripts:
    script_path = os.path.join(BASE_DIR, "training", script)

    if not os.path.exists(script_path):
        print(f"Missing script: {script}")
        exit(1)

    print(f"\nRunning {script}...")
    result = subprocess.run(["python", script_path, "--mode", "training"])

    if result.returncode != 0:
        print(f"{script} failed. Stopping pipeline.")
        exit(1)

print("\nPipeline completed successfully.")