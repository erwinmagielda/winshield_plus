import os
import json
import subprocess
from datetime import datetime


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAINING_DIR = os.path.join(BASE_DIR, "training")
RESULTS_DIR = os.path.join(BASE_DIR, "results")

os.makedirs(RESULTS_DIR, exist_ok=True)

RESULTS_PATH = os.path.join(RESULTS_DIR, "pipeline_completion.json")


# ------------------------------------------------------------
# PIPELINE SCRIPTS
# ------------------------------------------------------------

SCRIPTS = [
    "flatten.py",
    "enrich.py",
    "label.py",
    "validate.py",
    "preprocess.py"
]


# ------------------------------------------------------------
# RUN PIPELINE
# ------------------------------------------------------------

def run_pipeline():

    completed = []

    for script in SCRIPTS:

        script_path = os.path.join(TRAINING_DIR, script)

        if not os.path.exists(script_path):
            print(f"Missing script: {script}")
            exit(1)

        print(f"\nRunning {script}...")

        result = subprocess.run(
            ["python", script_path, "--mode", "training"]
        )

        if result.returncode != 0:
            print(f"{script} failed. Stopping pipeline.")
            exit(1)

        completed.append(script)

    summary = {
        "timestamp": datetime.utcnow().isoformat(),
        "scripts_executed": completed,
        "status": "success"
    }

    with open(RESULTS_PATH, "w") as f:
        json.dump(summary, f, indent=4)

    print("\nPipeline completed successfully.")
    print(f"Pipeline summary saved to: {RESULTS_PATH}")


# ------------------------------------------------------------
# ENTRYPOINT
# ------------------------------------------------------------

if __name__ == "__main__":
    run_pipeline()