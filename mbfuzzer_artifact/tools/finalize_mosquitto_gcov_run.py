import json
import os
import subprocess
import sys
import time
from pathlib import Path


def wait_for_pid_exit(pid: int) -> int:
    while True:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return 0
        except PermissionError:
            return 1
        time.sleep(5)


def run_command(command):
    completed = subprocess.run(command, capture_output=True, text=True)
    return completed.returncode, completed.stdout, completed.stderr


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def save_json(path: Path, payload):
    with path.open("w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2)
        file.write("\n")


def update_report(report_path: Path, coverage_text: str):
    if not report_path.exists():
        return

    content = report_path.read_text(encoding="utf-8")
    content = content.replace(
        "Coverage Value: unavailable in current local run",
        f"Coverage Value: {coverage_text}",
    )
    content = content.replace(
        "Coverage Comparable to Paper: False",
        "Coverage Comparable to Paper: True",
    )
    content = content.replace(
        "- Branch coverage requires a gcov-instrumented C/C++ broker build and is not collected in the current local run.\n",
        "- Branch coverage was collected from the gcov-instrumented mosquitto 2.0.18 build using gcovr.\n",
    )
    report_path.write_text(content, encoding="utf-8")


def main():
    if len(sys.argv) != 5:
        raise SystemExit(
            "Usage: finalize_mosquitto_gcov_run.py <fuzz_pid> <container_name> <fuzz_output_dir> <coverage_dir>"
        )

    fuzz_pid = int(sys.argv[1])
    container_name = sys.argv[2]
    fuzz_output_dir = Path(sys.argv[3])
    coverage_dir = Path(sys.argv[4])

    wait_for_pid_exit(fuzz_pid)

    coverage_dir.mkdir(parents=True, exist_ok=True)

    returncode, stdout, stderr = run_command(
        [
            "docker",
            "exec",
            container_name,
            "/usr/local/bin/mosquitto_gcov_collect.sh",
            "/opt/mosquitto-gcov",
            "/coverage",
        ]
    )

    postprocess_log = coverage_dir / "postprocess.log"
    postprocess_log.write_text(
        "[docker exec exit code]\n"
        + str(returncode)
        + "\n\n[stdout]\n"
        + stdout
        + "\n\n[stderr]\n"
        + stderr,
        encoding="utf-8",
    )

    if returncode != 0:
        raise SystemExit(returncode)

    summary_json_path = coverage_dir / "gcovr-summary.json"
    if not summary_json_path.exists():
        raise SystemExit("Missing gcovr summary JSON after collection")

    coverage_summary = load_json(summary_json_path)
    branch_covered = coverage_summary.get("branch_covered")
    branch_total = coverage_summary.get("branch_total")
    branch_percent = coverage_summary.get("branch_percent")

    if branch_covered is None or branch_total is None:
        raise SystemExit("gcovr summary JSON missing branch coverage keys")

    paper_metrics_path = fuzz_output_dir / "paper_metrics.json"
    if paper_metrics_path.exists():
        paper_metrics = load_json(paper_metrics_path)
    else:
        paper_metrics = {}

    paper_scope = paper_metrics.setdefault("paper_metric_scope", {})
    paper_scope["coverage_metric"] = "branch coverage"
    paper_scope["coverage_value"] = branch_covered
    paper_scope["coverage_status"] = "collected from gcovr summary"
    paper_scope["branch_covered"] = branch_covered
    paper_scope["branch_total"] = branch_total
    paper_scope["branch_percent"] = branch_percent

    comparability = paper_metrics.setdefault("paper_comparability", {})
    comparability["coverage_comparable"] = True

    notes = paper_metrics.setdefault("notes", [])
    replacement_note = "Branch coverage was collected from the gcov-instrumented mosquitto 2.0.18 build using gcovr."
    notes = [
        replacement_note if note == "Branch coverage requires a gcov-instrumented C/C++ broker build and is not collected in the current local run." else note
        for note in notes
    ]
    if replacement_note not in notes:
        notes.append(replacement_note)
    paper_metrics["notes"] = notes

    save_json(paper_metrics_path, paper_metrics)

    coverage_text = f"{branch_covered} covered branches ({branch_percent}%, {branch_covered}/{branch_total})"
    update_report(fuzz_output_dir / "fuzzing_report.txt", coverage_text)

    branch_summary_path = coverage_dir / "paper_branch_coverage.json"
    save_json(
        branch_summary_path,
        {
            "metric": "branch coverage",
            "branch_covered": branch_covered,
            "branch_total": branch_total,
            "branch_percent": branch_percent,
            "source": "gcovr-summary.json",
            "paper_comparable": True,
        },
    )


if __name__ == "__main__":
    main()
