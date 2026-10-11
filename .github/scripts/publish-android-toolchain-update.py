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

"""Publish Android toolchain updates and recover interrupted PR/CI creation."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess

SPEC = importlib.util.spec_from_file_location("android_toolchain", Path(__file__).with_name("update-android-toolchain.py"))
UPDATER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UPDATER)


def command(*args: str) -> str:
    # Git blobs must retain CRLFs, blank lines and surrounding whitespace for
    # exact comparison. Trim only metadata at its individual call sites.
    return subprocess.check_output(args).decode("utf-8")


def properties(text: str) -> tuple[str, dict[str, str]]:
    """Normalize only the three owned pins, retaining all other content for comparison."""
    pins = UPDATER.pinned_properties(text)
    for key in UPDATER.PACKAGES:
        text = UPDATER.property_pattern(key).sub(lambda match: match[1] + "<tool-pin>" + match[3], text)
    return text, pins


def validate_property_update(original: str, published: str, report: dict) -> None:
    old_text, old_pins = properties(original)
    new_text, new_pins = properties(published)
    if old_text != new_text:
        raise ValueError("Update changes unrelated Gradle properties")
    if any(UPDATER.version(new_pins[key]) < UPDATER.version(old_pins[key]) for key in old_pins):
        raise ValueError("Update downgrades a tool pin")
    for item in report["changes"]:
        if new_pins[item["property"]] != item["to"]:
            raise ValueError("Update has different target tool versions")
    if UPDATER.target_branch(published) != report["branch"]:
        raise ValueError("Update does not match its complete target pin set")


def validate_existing_branch(report: dict, run=command) -> str:
    """An orphan ref must contain only this bot's tool updates before opening a PR."""
    base = run("git", "merge-base", "HEAD", "FETCH_HEAD").strip()
    if run("git", "diff", "--name-only", base, "FETCH_HEAD").strip() != "gradle.properties":
        raise ValueError("Existing bot branch contains unexpected changed files")
    validate_property_update(run("git", "show", f"{base}:gradle.properties"),
                             run("git", "show", "FETCH_HEAD:gradle.properties"), report)
    return run("git", "rev-parse", "FETCH_HEAD").strip()


def ensure_ci(branch: str, sha: str, run=command) -> None:
    # A PR created with GITHUB_TOKEN need not have runnable PR-event CI. Restrict
    # this lookup to explicit dispatches so approval-waiting PR runs do not hide it.
    runs = json.loads(run("gh", "run", "list", "--workflow", "ci.yml", "--branch", branch,
                          "--commit", sha, "--event", "workflow_dispatch", "--limit", "1",
                          "--json", "databaseId"))
    if not runs:
        run("gh", "workflow", "run", "ci.yml", "--ref", branch)
        print(f"Dispatched CI for {branch} at {sha}")
    else:
        print(f"CI already dispatched for {sha}")


def publish(report: dict, body_file: Path, base_branch: str, run=command) -> None:
    branch = report["branch"]
    if not branch:
        print("Android toolchain pins are already current")
        return
    if not re.fullmatch(r"bot/android-toolchain-[0-9a-f]{16}", branch):
        raise ValueError("Unexpected bot branch name")
    if not report["changes"]:
        raise ValueError("A bot branch requires a nonempty update report")
    for item in report["changes"]:
        if item["property"] not in UPDATER.PACKAGES:
            raise ValueError("Unexpected property in update report")
        if UPDATER.version(item["to"]) <= UPDATER.version(item["from"]):
            raise ValueError("Update report must contain upgrades")

    prs = json.loads(run("gh", "pr", "list", "--state", "all", "--head", branch,
                         "--base", base_branch, "--limit", "1", "--json", "number,state,headRefOid"))
    if prs and prs[0]["state"] != "OPEN":
        print(f"Respecting closed/merged pull request #{prs[0]['number']}")
        return
    remote = run("git", "ls-remote", "--heads", "origin", f"refs/heads/{branch}").strip()
    if remote:
        run("git", "fetch", "origin", f"refs/heads/{branch}")
        sha = validate_existing_branch(report, run)
    else:
        if prs:
            raise ValueError("Open update PR has no remote branch")
        run("git", "switch", "-c", branch)
        run("git", "add", "--", "gradle.properties")
        if run("git", "diff", "--cached", "--name-only").strip() != "gradle.properties":
            raise ValueError("Refusing to commit unrelated staged files")
        staged = run("git", "show", ":gradle.properties")
        if UPDATER.target_branch(staged) != branch:
            raise ValueError("Staged properties do not match the target pin set")
        original = run("git", "show", "HEAD:gradle.properties")
        validate_property_update(original, staged, report)
        old_pins = UPDATER.pinned_properties(original)
        new_pins = UPDATER.pinned_properties(staged)
        actual = [{"property": key, "from": old_pins[key], "to": new_pins[key]}
                  for key in UPDATER.PACKAGES if old_pins[key] != new_pins[key]]
        if actual != report["changes"]:
            raise ValueError("Update report does not match the checked-out base pins")
        run("git", "-c", "user.name=github-actions[bot]", "-c",
            "user.email=41898282+github-actions[bot]@users.noreply.github.com", "commit", "-m",
            "chore(deps): update stable Android toolchain pins")
        run("git", "push", "origin", f"HEAD:refs/heads/{branch}")
        sha = run("git", "rev-parse", "HEAD").strip()

    if prs:
        if prs[0]["headRefOid"] != sha:
            raise ValueError("PR head changed during publication; retry from a fresh checkout")
    else:
        run("gh", "pr", "create", "--base", base_branch, "--head", branch, "--title",
            "chore(deps): update stable Android toolchain pins", "--body-file", str(body_file))
    # Always reach this path for open PRs: a failure after PR creation or a remote
    # push can be recovered next run without duplicates or rewriting commits.
    ensure_ci(branch, sha, run)


def main() -> None:
    directory = Path(os.environ["REPORT_DIR"])
    report = json.loads((directory / "report.json").read_text(encoding="utf-8"))
    publish(report, directory / "pr-body.md", os.environ["BASE_BRANCH"])


if __name__ == "__main__":
    main()
