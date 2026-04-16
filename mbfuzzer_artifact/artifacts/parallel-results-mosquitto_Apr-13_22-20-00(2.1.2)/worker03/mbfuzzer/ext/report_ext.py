"""
OCP Extension: paper-aligned fuzzing report & metrics.

Adds extra reporting **around** the original ``dump_fuzzing_info_log`` without
modifying its source.  The wrapper:

  1. Calls the *original* ``dump_fuzzing_info_log`` (unchanged).
  2. Appends a paper-aligned summary section to the report.
  3. Writes ``paper_metrics.json`` alongside the report.

The original ``directory_operation.py`` is NEVER modified.
"""

import os
import json
import datetime
import time

import globals as g
import helper_functions.directory_operation as do


# ── Pure helper functions (all NEW code) ──────────────────────────────────

def count_output_files(directory):
    """Count all files under *directory* recursively."""
    if not os.path.exists(directory):
        return 0
    total = 0
    for _, _, files in os.walk(directory):
        total += len(files)
    return total


def parse_existing_report_metrics():
    """Parse key metrics from an already-written ``fuzzing_report.txt``."""
    file_path = os.path.join(g.FUZZING_OUTPUT_DIR, "fuzzing_report.txt")
    metrics = {}
    if not os.path.exists(file_path):
        return metrics
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("Fuzzing Start Time: "):
                metrics["start_time"] = line.split(": ", 1)[1]
            elif line.startswith("Fuzzing End Time: "):
                metrics["end_time"] = line.split(": ", 1)[1]
            elif line.startswith("Fuzzing request number: "):
                value = line.split(": ", 1)[1]
                try:
                    metrics["messages_sent"] = int(value)
                except ValueError:
                    pass
    return metrics


def build_paper_aligned_summary(endtime):
    """Build a dict suitable for ``paper_metrics.json``."""
    existing_metrics = parse_existing_report_metrics()
    messages_sent = (do.total_messages_sent(g.CLIENT_SENT_MESSAGE)
                     + do.total_messages_sent(g.BROKER_SENT_MESSAGE))
    if messages_sent == 0:
        messages_sent = existing_metrics.get("messages_sent", 0)

    queue_files      = count_output_files(g.FUZZING_OUTPUT_QUEUE_DIR)
    valid_conn_files = count_output_files(g.FUZZING_OUTPUT_VALID_CON_DIR)
    diff_files       = count_output_files(g.FUZZING_OUTPUT_DIFF_DIR)
    crash_files      = count_output_files(g.FUZZING_OUTPUT_CRASH_DIR)
    single_broker    = len(g.DOCKER_CONTAINER) < 2

    runtime_seconds = int(max(0, endtime - g.FUZZING_START_TIME)) if g.FUZZING_START_TIME else 0
    if runtime_seconds == 0 and existing_metrics.get("start_time") and existing_metrics.get("end_time"):
        try:
            t0 = datetime.datetime.strptime(existing_metrics["start_time"], "%Y-%m-%d %H:%M:%S")
            t1 = datetime.datetime.strptime(existing_metrics["end_time"],   "%Y-%m-%d %H:%M:%S")
            runtime_seconds = int(max(0, (t1 - t0).total_seconds()))
        except ValueError:
            pass

    notes = [
        "The paper reports messages sent, branch coverage, and unique bug discovery results.",
        "Branch coverage requires a gcov-instrumented C/C++ broker build and is not collected in the current local run.",
        "Paper bug counts are unique reported/confirmed/fixed bugs after analysis, not raw seed-file counts.",
    ]
    if single_broker:
        notes.append(
            "This local run used single-broker mode, so non-compliance bug "
            "discovery is not directly comparable to the paper's six-broker "
            "differential setup."
        )

    return {
        "subjects": list(g.DOCKER_CONTAINER),
        "runtime_seconds": runtime_seconds,
        "messages_sent": messages_sent,
        "paper_metric_scope": {
            "coverage_metric":              "branch coverage",
            "coverage_value":               None,
            "coverage_status":              "unavailable in current local run",
            "memory_bug_reported":          None,
            "memory_bug_confirmed":         None,
            "memory_bug_fixed":             None,
            "non_compliance_bug_reported":  None,
            "non_compliance_bug_confirmed": None,
            "non_compliance_bug_fixed":     None,
        },
        "local_artifacts": {
            "crash_seed_files":           crash_files,
            "diff_seed_files":            diff_files,
            "queue_corpus_files":         queue_files,
            "valid_connect_seed_files":   valid_conn_files,
        },
        "paper_comparability": {
            "single_broker_mode":       single_broker,
            "coverage_comparable":      False,
            "bug_discovery_comparable": not single_broker,
        },
        "notes": notes,
    }


def paper_summary_to_text(summary):
    """Render *summary* dict as human-readable text lines."""
    ps = summary["paper_metric_scope"]
    la = summary["local_artifacts"]
    pc = summary["paper_comparability"]
    lines = [
        "Paper-aligned Local Summary:",
        "Subject: "                          + ", ".join(summary["subjects"]),
        "Runtime Seconds: "                  + str(summary["runtime_seconds"]),
        "Messages Sent: "                    + str(summary["messages_sent"]),
        "Coverage Metric (Paper): "          + ps["coverage_metric"],
        "Coverage Value: unavailable in current local run",
        "Memory Bug (Report/Confirmed/Fixed): unavailable from raw local artifacts",
        "Non-Compliance Bug (Report/Confirmed/Fixed): unavailable from raw local artifacts",
        "Crash Seed Files (Local): "         + str(la["crash_seed_files"]),
        "Diff Seed Files (Local): "          + str(la["diff_seed_files"]),
        "Queue Corpus Files (Local): "       + str(la["queue_corpus_files"]),
        "Valid Connect Seed Files (Local): " + str(la["valid_connect_seed_files"]),
        "Single Broker Mode: "               + str(pc["single_broker_mode"]),
        "Coverage Comparable to Paper: "     + str(pc["coverage_comparable"]),
        "Bug Discovery Comparable to Paper: "+ str(pc["bug_discovery_comparable"]),
        "Notes:",
    ]
    for note in summary["notes"]:
        lines.append("- " + note)
    return "\n".join(lines)


# ── Wrapper around the original dump function ─────────────────────────────

# Keep a reference to the ORIGINAL, unmodified function.
_original_dump = do.dump_fuzzing_info_log


def _extended_dump(Model=None):
    """
    Call the original ``dump_fuzzing_info_log`` first, then append the
    paper-aligned summary and write ``paper_metrics.json``.
    """
    # 1. Run original report (writes fuzzing_report.txt as-is)
    _original_dump(Model)

    # 2. Append paper summary to the same report file
    endtime = time.time()
    paper_summary = build_paper_aligned_summary(endtime)
    report_path = os.path.join(g.FUZZING_OUTPUT_DIR, "fuzzing_report.txt")
    with open(report_path, "a") as f:
        f.write("\n" + paper_summary_to_text(paper_summary) + "\n")

    # 3. Write machine-readable JSON
    json_path = os.path.join(g.FUZZING_OUTPUT_DIR, "paper_metrics.json")
    with open(json_path, "w") as f:
        json.dump(paper_summary, f, indent=2)


def apply():
    """
    Replace ``directory_operation.dump_fuzzing_info_log`` with the
    extended wrapper.  Every call site (fuzz.py, handle_exit, etc.)
    that already references ``do.dump_fuzzing_info_log`` will
    transparently pick up the wrapper because Python module objects
    are mutable namespaces.
    """
    do.dump_fuzzing_info_log = _extended_dump
