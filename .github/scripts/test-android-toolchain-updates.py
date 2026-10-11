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

"""Offline regression tests for the Android toolchain dependency updater."""

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("update-android-toolchain.py")
SPEC = importlib.util.spec_from_file_location("android_toolchain_updates", SCRIPT)
UPDATER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UPDATER)


def package(kind, value, *, channel="channel-0", preview=False, obsolete=False, host="linux", arch="x86_64"):
    parts = (value.split(".") + ["0", "0"])[:3]
    return f"""<remotePackage path="{kind};{value}" obsolete="{str(obsolete).lower()}">
      <revision><major>{parts[0]}</major><minor>{parts[1]}</minor><micro>{parts[2]}</micro>{'<preview>1</preview>' if preview else ''}</revision>
      <channelRef ref="{channel}"/>
      <archives><archive><complete><url>tool.zip</url></complete>
      <host-os>{host}</host-os><host-arch>{arch}</host-arch></archive></archives>
    </remotePackage>"""


def feed(*extra):
    packages = [package("ndk", "30.0.200"), package("cmake", "4.1.2"), package("build-tools", "37.0.0")]
    return ('<sdk:sdk-repository xmlns:sdk="http://schemas.android.com/sdk/android/repo/repository2/03">'
            + "".join(packages) + "".join(extra) + "</sdk:sdk-repository>").encode()


PROPERTIES = (
    "# Keep this comment and unrelated settings\n"
    "duckdetector.android.ndk=30.0.100\n"
    "duckdetector.android.cmake=4.1.2\n"
    "duckdetector.android.buildTools=37.0.0\n"
    "duckdetector.android.targetSdk=37\n"
)


class AndroidToolchainUpdatesTest(unittest.TestCase):
    def test_numeric_ordering(self):
        latest = UPDATER.latest_packages(feed(package("ndk", "30.0.1000"), package("ndk", "30.0.99")))
        self.assertEqual(latest["ndk"], "30.0.1000")

    def test_rejects_preview_even_on_stable_channel(self):
        latest = UPDATER.latest_packages(feed(package("ndk", "31.0.999", preview=True)))
        self.assertEqual(latest["ndk"], "30.0.200")

    def test_filters_unusable_packages(self):
        for options in ({"channel": "channel-1"}, {"obsolete": True}, {"host": "windows"}, {"arch": "aarch64"}, {"arch": "x86"}):
            with self.subTest(options=options):
                latest = UPDATER.latest_packages(feed(package("ndk", "31.0.999", **options)))
                self.assertEqual(latest["ndk"], "30.0.200")

    def test_older_four_part_cmake_versions_are_supported(self):
        latest = UPDATER.latest_packages(feed(package("cmake", "3.10.2.4988404")))
        self.assertEqual(latest["cmake"], "4.1.2")

    def test_missing_kind_or_invalid_document_fails(self):
        for xml in (b"<html/>", b"<sdk-repository/>", b"not xml"):
            with self.subTest(xml=xml), self.assertRaises((ValueError, UPDATER.ET.ParseError)):
                UPDATER.latest_packages(xml)

    def test_untrusted_version_is_rejected(self):
        with self.assertRaises(ValueError):
            UPDATER.latest_packages(feed(package("ndk", "31.0.invalid")))

    def test_namespaced_children_and_explicit_zero_preview(self):
        xml = feed().decode().replace('xmlns:sdk=', 'xmlns="urn:android-sdk" xmlns:sdk=')
        xml = xml.replace('</revision>', '<preview>0</preview></revision>')
        self.assertEqual(UPDATER.latest_packages(xml.encode())["ndk"], "30.0.200")

    def test_revision_must_match_package_path(self):
        wrong = package("ndk", "31.0.300").replace('<major>31</major>', '<major>30</major>')
        with self.assertRaisesRegex(ValueError, "path and revision disagree"):
            UPDATER.latest_packages(feed(wrong))

    def test_missing_archive_url_and_32_bit_host_are_not_candidates(self):
        for candidate in (package("ndk", "31.0.300").replace('<url>tool.zip</url>', ''),
                          package("ndk", "31.0.300").replace('</archive>', '<host-bits>32</host-bits></archive>')):
            self.assertEqual(UPDATER.latest_packages(feed(candidate))["ndk"], "30.0.200")

    def test_only_tool_pins_change(self):
        updated, changes = UPDATER.update_properties(PROPERTIES, UPDATER.latest_packages(feed()))
        self.assertEqual(updated, PROPERTIES.replace("ndk=30.0.100", "ndk=30.0.200"))
        self.assertEqual(changes, [{"property": "duckdetector.android.ndk", "from": "30.0.100", "to": "30.0.200"}])
        self.assertIn("| `duckdetector.android.ndk` | `30.0.100` | `30.0.200` |", UPDATER.pr_body(changes))

    def test_never_downgrades_or_reports_equal_versions(self):
        current = PROPERTIES.replace("ndk=30.0.100", "ndk=31.0.100")
        updated, changes = UPDATER.update_properties(current, UPDATER.latest_packages(feed()))
        self.assertEqual(updated, current)
        self.assertEqual(changes, [])

    def test_missing_duplicate_and_invalid_properties_fail(self):
        for text in (PROPERTIES.replace("duckdetector.android.cmake=4.1.2\n", ""),
                     PROPERTIES + "duckdetector.android.ndk=30.0.100\n",
                     PROPERTIES.replace("30.0.100", "invalid")):
            with self.subTest(text=text), self.assertRaises(ValueError):
                UPDATER.update_properties(text, UPDATER.latest_packages(feed()))

    def test_preserves_crlf_and_spacing(self):
        text = PROPERTIES.replace("ndk=", "ndk = ").replace("\n", "\r\n")
        updated, _ = UPDATER.update_properties(text, UPDATER.latest_packages(feed()))
        self.assertEqual(updated, text.replace("30.0.100", "30.0.200"))

    def test_partial_merge_does_not_create_a_different_target_branch(self):
        latest = {"ndk": "30.0.200", "cmake": "4.2.0", "build-tools": "37.0.0"}
        both, changes = UPDATER.update_properties(PROPERTIES, latest)
        partial, remaining = UPDATER.update_properties(PROPERTIES.replace("30.0.100", "30.0.200"), latest)
        self.assertEqual((len(changes), len(remaining)), (2, 1))
        self.assertEqual(UPDATER.target_branch(both), UPDATER.target_branch(partial))
        self.assertEqual(UPDATER.target_branch(both), UPDATER.target_branch(both + '# unrelated comment\n'))

    def run_updater(self, properties, xml, output):
        return subprocess.run([sys.executable, str(SCRIPT), "--properties", str(properties),
                               "--repository-xml", str(xml), "--output-dir", str(output)],
                              capture_output=True, text=True)

    def test_cli_update_then_noop(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            props, xml, output = root / "gradle.properties", root / "repository.xml", root / "output"
            props.write_text(PROPERTIES)
            xml.write_bytes(feed())
            result = self.run_updater(props, xml, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = UPDATER.json.loads((output / "report.json").read_text())
            self.assertRegex(report["branch"], r"^bot/android-toolchain-[0-9a-f]{16}$")
            self.assertTrue((output / "pr-body.md").exists())
            result = self.run_updater(props, xml, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(UPDATER.json.loads((output / "report.json").read_text())["branch"], "")
            self.assertFalse((output / "pr-body.md").exists())

    def test_cli_error_keeps_properties_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            props, xml = root / "gradle.properties", root / "repository.xml"
            props.write_text(PROPERTIES.replace("duckdetector.android.cmake=4.1.2\n", ""))
            original = props.read_bytes()
            xml.write_bytes(feed())
            output = root / "output"
            output.mkdir()
            (output / "report.json").write_text('stale report')
            (output / "pr-body.md").write_text('stale body')
            result = self.run_updater(props, xml, root / "output")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(props.read_bytes(), original)
            self.assertFalse((root / "output" / "report.json").exists())
            self.assertFalse((root / "output" / "pr-body.md").exists())


if __name__ == "__main__":
    unittest.main()
