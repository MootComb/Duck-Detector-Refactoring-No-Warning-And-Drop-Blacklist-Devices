#!/usr/bin/env python3
"""Compile and verify the production latency classifier on the build host."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
NATIVE = ROOT.parents[1] / "main/cpp"
compiler = shutil.which("c++")
if not compiler:
    raise RuntimeError("A host C++ compiler is required")
with tempfile.TemporaryDirectory(prefix="kernelpatch-latency-test-") as directory:
    executable = Path(directory) / "latency-test"
    subprocess.run([
        compiler, "-std=c++20", "-Wall", "-Wextra", "-Werror", "-I", str(NATIVE),
        str(NATIVE / "nativeroot/probes/kernelpatch_latency_evidence.cpp"),
        str(ROOT / "kernelpatch_latency_evidence_test.cpp"), "-o", str(executable),
    ], check=True)
    subprocess.run([str(executable)], check=True, timeout=10)
print("Latency calibration samples, threshold boundaries, invalid timing and evidence limits passed")
