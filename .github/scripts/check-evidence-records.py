#!/usr/bin/env python3
# Copyright (C) 2026 Duck Apps Contributor
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Fail when a detector or capability lacks a complete evidence record.

AGENTS.md section 12 asks every detector signal to be explainable from the observable signal to
DuckDetector's interpretation. Each detector (a feature directory with a detector module) and each
capability keeps that chain in its own EVIDENCE.md. Every entry under "## Signals" must fill all of
the chain's fields, and its references must name a primary source, or say "Discovery only:" when
the signal rests on observed tool behaviour or an unreviewed source. A record marked
"Status: draft", as the detector scaffold writes it, fails until the research is recorded.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

RECORD = "EVIDENCE.md"
FIELDS = (
    "Observable signal",
    "Producing subsystem",
    "Mechanism",
    "References",
    "Applicability",
    "Visibility limits",
    "Result states",
    "Interpretation",
)
DISCOVERY_MARKER = "Discovery only:"
PRIMARY_SOURCE = re.compile(
    r"frameworks/|system/|bionic|\bart/|packages/modules/|hardware/interfaces|external/|build/soong|"
    r"\bcts/|platform/cts|kernel/common|source\.android\.com|developer\.android\.com|Android CDD|\bCDD\b|"
    r"Arm Architecture Reference Manual|\bArm ARM\b|Intel SDM|AMD64 APM|\bNVD\b|CVE-\d{4}-\d+|"
    r"kernel\.org|\bRFC \d+"
)
FIELD_LINE = re.compile(r"^- ([A-Za-z ]+):(.*)$")


def iter_units(repo_root: str):
    """Yield (unit, directory) for every detector feature and every capability."""
    features = os.path.join(repo_root, "feature")
    if os.path.isdir(features):
        for name in sorted(os.listdir(features)):
            if os.path.isfile(os.path.join(features, name, "detector", "build.gradle.kts")):
                yield f"feature/{name}", os.path.join(features, name)
    capabilities = os.path.join(repo_root, "capability")
    if os.path.isdir(capabilities):
        for name in sorted(os.listdir(capabilities)):
            if os.path.isdir(os.path.join(capabilities, name)):
                yield f"capability/{name}", os.path.join(capabilities, name)


def signal_entries(lines: list[str]) -> list[tuple[str, list[str]]] | None:
    """The ### entries under ## Signals, or None when the section is missing."""
    try:
        start = lines.index("## Signals")
    except ValueError:
        return None
    entries: list[tuple[str, list[str]]] = []
    for line in lines[start + 1:]:
        if line.startswith("## "):
            break
        if line.startswith("### "):
            entries.append((line[4:].strip(), []))
        elif entries:
            entries[-1][1].append(line)
    return entries


def entry_fields(body: list[str]) -> dict[str, list[str]]:
    """Field name to its values; a field continues on the following indented lines."""
    fields: dict[str, list[str]] = {}
    current: str | None = None
    for line in body:
        match = FIELD_LINE.match(line)
        if match and match.group(1) in FIELDS:
            current = match.group(1)
            fields.setdefault(current, []).append(match.group(2).strip())
        elif current and line.startswith("  ") and line.strip():
            fields[current][-1] = (fields[current][-1] + " " + line.strip()).strip()
        elif not line.strip():
            continue
        else:
            current = None
    return fields


def check_record(unit: str, text: str) -> tuple[list[str], int, int]:
    errors: list[str] = []
    lines = text.split("\n")
    heading = next((line for line in lines if line.strip()), "")
    if not (heading.startswith("# ") and heading.rstrip().endswith("evidence record")):
        errors.append(f"{unit}/{RECORD} must open with a '# ... evidence record' heading")
    if "Status: draft" in lines:
        errors.append(f"{unit}/{RECORD} is still a draft; record the research and set 'Status: reviewed'")
    elif "Status: reviewed" not in lines:
        errors.append(f"{unit}/{RECORD} needs a 'Status: reviewed' line")
    entries = signal_entries(lines)
    if entries is None:
        return errors + [f"{unit}/{RECORD} has no '## Signals' section"], 0, 0
    if not entries:
        return errors + [f"{unit}/{RECORD} lists no signal under '## Signals'"], 0, 0
    discovery = 0
    for name, body in entries:
        fields = entry_fields(body)
        for field in FIELDS:
            values = fields.get(field, [])
            if len(values) != 1:
                errors.append(f"{unit}/{RECORD} signal '{name}' needs exactly one '- {field}:' line")
            elif not values[0]:
                errors.append(f"{unit}/{RECORD} signal '{name}' leaves '{field}' empty")
        references = fields.get("References", [""])[0] if len(fields.get("References", [])) == 1 else ""
        if references.startswith(DISCOVERY_MARKER):
            discovery += 1
        elif references and not PRIMARY_SOURCE.search(references):
            errors.append(
                f"{unit}/{RECORD} signal '{name}' cites no primary source; name one, "
                f"or start its references with '{DISCOVERY_MARKER}'"
            )
    return errors, len(entries), discovery


def check(repo_root: str) -> tuple[list[str], int, int, int]:
    errors: list[str] = []
    units = signals = discovery = 0
    for unit, directory in iter_units(repo_root):
        units += 1
        path = os.path.join(directory, RECORD)
        if not os.path.isfile(path):
            errors.append(f"{unit} has no {RECORD}")
            continue
        with open(path, encoding="utf-8") as handle:
            record_errors, record_signals, record_discovery = check_record(unit, handle.read())
        errors.extend(record_errors)
        signals += record_signals
        discovery += record_discovery
    return errors, units, signals, discovery


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    default_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    parser.add_argument("--repo-root", default=default_root)
    arguments = parser.parse_args(argv)
    errors, units, signals, discovery = check(os.path.abspath(arguments.repo_root))
    if errors:
        for error in errors:
            print(f"evidence record violation: {error}", file=sys.stderr)
        return 1
    print(f"Evidence records verified: {units} units, {signals} signal entries, {discovery} discovery-only.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
