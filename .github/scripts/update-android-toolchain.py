#!/usr/bin/env python3
# Copyright (C) 2026 Duck Apps Contributor
# If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

"""Update Android tool pins from Google's SDK repository, without running Gradle."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import urllib.request
import xml.etree.ElementTree as ET

REPOSITORY_URL = "https://dl.google.com/android/repository/repository2-3.xml"
PACKAGES = {
    "duckdetector.android.ndk": "ndk",
    "duckdetector.android.cmake": "cmake",
    "duckdetector.android.buildTools": "build-tools",
}


def version(value: str) -> tuple[int, ...]:
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){2,3}", value):
        raise ValueError(f"Unsupported Android tool version: {value!r}")
    return tuple(int(part) for part in value.split("."))


def latest_packages(xml: bytes) -> dict[str, str]:
    root = ET.fromstring(xml)
    if root.tag.rsplit("}", 1)[-1] != "sdk-repository":
        raise ValueError("Expected an Android SDK repository document")
    # SDK feeds normally qualify only the root. Also accept consistently
    # namespaced child elements without silently finding zero packages.
    for element in root.iter():
        element.tag = element.tag.rsplit("}", 1)[-1]
    candidates: dict[str, list[str]] = {name: [] for name in PACKAGES.values()}
    for package in root.findall("remotePackage"):
        kind, separator, value = package.get("path", "").partition(";")
        if not separator or kind not in candidates:
            continue
        channel = package.find("channelRef")
        revision = package.find("revision")
        # Some NDK previews are published on channel-0 too. Both checks matter.
        if channel is not None and channel.get("ref") != "channel-0":
            continue
        if revision is None or int(revision.findtext("preview", "0")) != 0:
            continue
        if package.get("obsolete", "false").lower() == "true":
            continue
        archives = package.findall("archives/archive")
        if not any(
            archive.find("complete") is not None
            and bool(archive.findtext("complete/url", "").strip())
            and archive.findtext("host-os", "linux") == "linux"
            and archive.findtext("host-arch", "x86_64") in ("x86_64", "amd64")
            and archive.findtext("host-bits", "64") == "64"
            for archive in archives
        ):
            continue
        path_version = version(value)
        revision_version = tuple(int(revision.findtext(part, "0")) for part in ("major", "minor", "micro"))
        if path_version[:3] != revision_version:
            raise ValueError(f"SDK package path and revision disagree: {kind};{value}")
        candidates[kind].append(value)
    latest = {}
    for kind, values in candidates.items():
        if not values:
            raise ValueError(f"No stable Linux SDK package found for {kind}")
        latest[kind] = max(values, key=version)
    return latest


def property_pattern(key: str) -> re.Pattern:
    return re.compile(r"^(" + re.escape(key) + r"[ \t]*=[ \t]*)([^\s#]+)([ \t]*\r?)$", re.MULTILINE)


def pinned_properties(text: str) -> dict[str, str]:
    pins = {}
    for key in PACKAGES:
        matches = list(property_pattern(key).finditer(text))
        if len(matches) != 1:
            raise ValueError(f"Expected exactly one {key} property")
        pins[key] = matches[0].group(2)
        version(pins[key])
    return pins


def target_branch(text: str) -> str:
    # Hash the complete final pin set, not just the delta. If a maintainer
    # accepts one pin separately, the remaining updates still reuse the same PR.
    targets = "\n".join(f"{key}={value}" for key, value in sorted(pinned_properties(text).items()))
    digest = hashlib.sha256(targets.encode()).hexdigest()[:16]
    return f"bot/android-toolchain-{digest}"


def update_properties(text: str, latest: dict[str, str]) -> tuple[str, list[dict[str, str]]]:
    changes = []
    pins = pinned_properties(text)
    for key, kind in PACKAGES.items():
        current = pins[key]
        target = latest[kind]
        if version(target) > version(current):
            text = property_pattern(key).sub(lambda match: match[1] + target + match[3], text)
            changes.append({"property": key, "from": current, "to": target})
    return text, changes


def pr_body(changes: list[dict[str, str]]) -> str:
    rows = "\n".join(f"| `{item['property']}` | `{item['from']}` | `{item['to']}` |" for item in changes)
    return (
        "## Summary\n\nUpdate the centrally pinned Android build tools.\n\n"
        "| Property | Current | Available stable version |\n| --- | --- | --- |\n" + rows
        + "\n\n## Sources / Provenance\n\n"
        + f"- Official Android SDK repository: {REPOSITORY_URL}\n"
        + "- Independently implemented repository automation; no third-party code copied.\n"
        + "- Generated by github-actions[bot] using the repository's updater.\n\n"
        + "## Validation\n\n"
        + "- Versions have stable channels, no preview revisions, and Linux archives.\n"
        + "- Only gradle.properties is updated; the build and CI read the same pins.\n"
        + "- The CI workflow is dispatched on this branch for build verification.\n"
        + "- No automatic merge. Review CI and compatibility before merging.\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--properties", type=Path, default=Path("gradle.properties"))
    parser.add_argument("--repository-xml", type=Path, help="Use an offline SDK repository fixture")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    # Reusing an output directory after an error/no-op must never expose an old
    # report or PR body as if it belonged to the current invocation.
    for name in ("report.json", "pr-body.md"):
        (args.output_dir / name).unlink(missing_ok=True)
    if args.repository_xml:
        xml = args.repository_xml.read_bytes()
    else:
        request = urllib.request.Request(REPOSITORY_URL, headers={"User-Agent": "DuckDetector-dependency-bot"})
        with urllib.request.urlopen(request, timeout=60) as response:
            xml = response.read()
    original = args.properties.read_bytes().decode("utf-8")
    updated, changes = update_properties(original, latest_packages(xml))
    report = {"changes": changes, "branch": ""}
    if changes:
        report["branch"] = target_branch(updated)
        (args.output_dir / "pr-body.md").write_text(pr_body(changes), encoding="utf-8")
        args.properties.write_bytes(updated.encode("utf-8"))
    (args.output_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
