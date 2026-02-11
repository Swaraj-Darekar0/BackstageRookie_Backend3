import os
import sys
import json
import pprint
import logging
from pathlib import Path

# Ensure project root is on PYTHONPATH when running as a script
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from analysis_engine.orchestrator import AnalysisOrchestrator  
from backend.app.services.repo_info_service import RepoInfoExtractor  

# --------------------------------------------------
# BASIC LOGGING (helps debug analyzer flow)
# --------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s | %(name)s | %(message)s"
)

# --------------------------------------------------
# CONFIG — CHANGE THIS ONLY
# --------------------------------------------------
REPO_PATH = r"D:\Downloads\Project\SecurityMongul\backend\PulledCode\June-Voice-AI"
PLAN = "full"   # or "basic"

# --------------------------------------------------
# TEST RUNNER
# --------------------------------------------------
def run_orchestration_test():
    if not os.path.exists(REPO_PATH):
        raise FileNotFoundError(f"Repo path does not exist: {REPO_PATH}")

    print("\n==============================")
    print(" ORCHESTRATION TEST STARTED ")
    print("==============================\n")

    # 1️⃣ Extract repository info (same as production)
    print("[1] Extracting repository information...")
    repo_info_extractor = RepoInfoExtractor()
    repository_info = repo_info_extractor.extract(REPO_PATH)

    print("✔ Repository info extracted\n")

    # 2️⃣ Initialize orchestrator
    print("[2] Initializing AnalysisOrchestrator...")
    orchestrator = AnalysisOrchestrator(plan=PLAN)

    print("✔ Orchestrator initialized\n")

    # 3️⃣ Run orchestration
    print("[3] Running analysis orchestration...")
    findings, metrics = orchestrator.run(
        repo_path=REPO_PATH,
        repository_info=repository_info
    )

    print("✔ Analysis completed\n")

    # 4️⃣ Pretty-print results
  

    print("\n==============================")
    print(" METRICS ")
    print("==============================")
    pprint.pprint(metrics)

    print("\n==============================")
    print(f" FINDINGS ({len(findings)}) ")
    print("==============================")

    for idx, finding in enumerate(findings, 1):
        print(f"\n[{idx}]")
        pprint.pprint(finding)

    # 5️⃣ Optional: save output locally
    output_path = "orchestration_test_output.json"
    with open(output_path, "w") as f:
        json.dump(
            {
                
                "metrics": metrics,
                "findings": findings
            },
            f,
            indent=2
        )

    print(f"\n✔ Results written to: {output_path}")
    print("\n==============================")
    print(" ORCHESTRATION TEST FINISHED ")
    print("==============================\n")


# --------------------------------------------------
# ENTRY POINT
# --------------------------------------------------
if __name__ == "__main__":
    run_orchestration_test()
