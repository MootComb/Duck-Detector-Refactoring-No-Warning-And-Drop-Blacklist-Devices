#!/usr/bin/env python3
# Copyright 2026 Duck Apps Contributor
# If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
# SPDX-License-Identifier: Apache-2.0
"""Run the actual channel transition with an in-memory GitHub transport and real files."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from subprocess import CompletedProcess
import tempfile
import unittest
from unittest.mock import patch

import nightly_channel as channel
import nightly_release

SHA = 'a' * 40
TAG = 'nightly-2026-10-18-aaaaaaaa'
REPO = 'example/repository'


class GitHubFixture:
    def __init__(self):
        self.events = []
        self.fail_upload = None
        self.starter = False
        self.archive = {'schemaVersion': 1, 'channel': 'nightly', 'branch': 'master', 'releaseTag': TAG,
                        'versionName': '2026.10.18-test', 'versionCode': 500, 'builtAtUtc': '2026-10-18T00:00:00Z', 'commit': {'sha': SHA}}
        self.files = {TAG: {}}
        for key, name in [('apk', 'build-' + TAG + '.apk'), ('sdk', 'sdk-' + TAG + '.aar')]:
            payload = (key + ' archive').encode()
            self.files[TAG][name] = payload
            self.archive[key] = {'name': name, 'sizeBytes': len(payload),
                                 'sha256': hashlib.sha256(payload).hexdigest(),
                                 'downloadUrl': f'https://github.com/{REPO}/releases/download/{TAG}/{name}'}
        self.files[TAG]['update.json'] = json.dumps(self.archive).encode()
        self.old = {'versionCode': 499, 'builtAtUtc': '2026-10-17T00:00:00Z'}
        self.files['update'] = {'update.json': json.dumps(self.old).encode()}
        self.draft = {TAG: False, 'update': False}
        self.immutable = {TAG: True, 'update': False}
        self.refs = {TAG: SHA, 'update': 'b' * 40}

    def api(self, *args, **kwargs):
        self.events.append(args)
        if args[0] == 'api':
            if '--paginate' in args:
                tag = 'update' if '/releases/10/' in args[-1] else TAG
                return [[{'name': name, 'size': len(data), 'state': 'starter' if tag == 'update' and self.starter else 'uploaded'} for name, data in self.files[tag].items()]]
            endpoint = args[1]
            if '/git/ref/tags/' in endpoint:
                tag = endpoint.rsplit('/', 1)[1]
                return {'object': {'type': 'commit', 'sha': self.refs[tag]}} if tag in self.refs else None
            tag = endpoint.rsplit('/', 1)[1]
            if tag not in self.files and kwargs.get('missing_ok'):
                return None
            return {'id': 10 if tag == 'update' else 20, 'tag_name': tag, 'prerelease': True, 'draft': self.draft[tag], 'immutable': self.immutable[tag],
                    'assets': [{'name': name, 'size': len(data), 'state': 'uploaded'}
                               for name, data in self.files[tag].items()]}
        raise AssertionError(args)

    def run(self, args, **kwargs):
        self.events.append(tuple(args))
        operation, tag = args[2], args[3]
        if operation == 'download':
            name = args[args.index('--pattern') + 1]
            directory = Path(args[args.index('--dir') + 1])
            (directory / name).write_bytes(self.files[tag][name])
        elif operation == 'upload':
            path = Path(args[4])
            if self.fail_upload == path.name:
                self.fail_upload = None
                self.files[tag].pop(path.name, None)
                raise RuntimeError('upload failed after removing previous pointer')
            self.files[tag][path.name] = path.read_bytes()
            self.starter = False
        else:
            raise AssertionError(args)
        return CompletedProcess(args, 0)


class ChannelTest(unittest.TestCase):
    def setUp(self):
        self.fake = GitHubFixture()
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        for owner, name, effect in [(channel, 'gh', self.fake.api), (nightly_release, 'gh', self.fake.api),
                                     (channel.subprocess, 'run', self.fake.run)]:
            mock = patch.object(owner, name, side_effect=effect)
            mock.start()
            self.addCleanup(mock.stop)

    def advance(self):
        return channel.advance(REPO, TAG, SHA, Path(self.directory.name), 'Telegram.apk')

    def test_only_exact_archive_manifest_is_uploaded_and_tag_never_moves(self):
        original = deepcopy(self.fake.files[TAG])
        channel_ref = self.fake.refs['update']
        advanced, apk_path = self.advance()
        self.assertTrue(advanced)
        self.assertEqual({'update.json': original['update.json']}, self.fake.files['update'])
        self.assertEqual(original, self.fake.files[TAG])
        uploads = [event[4] for event in self.fake.events if event[:3] == ('gh', 'release', 'upload')]
        self.assertEqual(['update.json'], [Path(path).name for path in uploads])
        self.assertEqual(original[self.fake.archive['apk']['name']], apk_path.read_bytes())
        self.assertEqual(channel_ref, self.fake.refs['update'])
        self.assertTrue(all(event[0] == 'api' and '-X' not in event
                            for event in self.fake.events if event[0] != 'gh'))

    def test_unpublished_archive_cannot_advance_channel(self):
        self.fake.draft[TAG] = True
        before = deepcopy(self.fake.files['update'])
        with self.assertRaises(ValueError):
            self.advance()
        self.assertEqual(before, self.fake.files['update'])

    def test_corrupt_archive_stops_before_channel_pointer_changes(self):
        self.fake.files[TAG][self.fake.archive['apk']['name']] = b'wrong bytes'
        before = self.fake.files['update']['update.json']
        with self.assertRaises(ValueError):
            self.advance()
        self.assertEqual(before, self.fake.files['update']['update.json'])

    def test_pointer_upload_failure_restores_previous_manifest(self):
        self.fake.fail_upload = 'update.json'
        before = self.fake.files['update']['update.json']
        with self.assertRaises(RuntimeError):
            self.advance()
        self.assertEqual(before, self.fake.files['update']['update.json'])

    def test_older_build_cannot_roll_the_channel_back(self):
        newer = dict(self.fake.old, versionCode=501)
        self.fake.files['update']['update.json'] = json.dumps(newer).encode()
        self.assertEqual((False, None), self.advance())
        self.assertEqual(newer, json.loads(self.fake.files['update']['update.json']))
        self.assertFalse(any(event[:3] == ('gh', 'release', 'upload') for event in self.fake.events))

    def test_rerun_leaves_archive_channel_pointer_and_ref_unchanged(self):
        self.advance()
        snapshot = deepcopy(self.fake.files)
        refs = deepcopy(self.fake.refs)
        self.fake.events.clear()
        advanced, _ = self.advance()
        self.assertFalse(advanced)
        self.assertEqual(snapshot, self.fake.files)
        self.assertEqual(refs, self.fake.refs)
        self.assertFalse(any(event[:3] == ('gh', 'release', 'upload') for event in self.fake.events))

    def test_missing_pointer_can_be_repaired_without_recreating_release(self):
        self.fake.files['update'].clear()
        self.assertTrue(self.advance()[0])
        self.assertEqual({'update.json': self.fake.files[TAG]['update.json']}, self.fake.files['update'])

    def test_failed_upload_starter_asset_can_be_replaced(self):
        self.fake.files['update']['update.json'] = b''
        self.fake.starter = True
        self.assertTrue(self.advance()[0])
        self.assertEqual({'update.json': self.fake.files[TAG]['update.json']}, self.fake.files['update'])

    def test_missing_channel_is_never_recreated(self):
        del self.fake.files['update']
        before = deepcopy(self.fake.files[TAG])
        with self.assertRaisesRegex(ValueError, 'never recreate'):
            self.advance()
        self.assertEqual(before, self.fake.files[TAG])
        self.assertFalse(any(event[:2] == ('release', 'create') for event in self.fake.events))

    def test_locked_or_draft_channel_is_rejected_before_mutation(self):
        before = deepcopy(self.fake.files)
        for state, key in [(self.fake.immutable, 'immutable'), (self.fake.draft, 'draft')]:
            with self.subTest(key=key):
                state['update'] = True
                with self.assertRaisesRegex(ValueError, 'mutable update'):
                    self.advance()
                state['update'] = False
        self.assertEqual(before, self.fake.files)

    def test_mutable_archive_cannot_advance_channel(self):
        self.fake.immutable[TAG] = False
        before = deepcopy(self.fake.files['update'])
        with self.assertRaisesRegex(ValueError, 'must be immutable'):
            self.advance()
        self.assertEqual(before, self.fake.files['update'])

    def test_any_binary_in_update_release_blocks_publication(self):
        self.fake.files['update']['unexpected.apk'] = b'another build'
        before = deepcopy(self.fake.files)
        with self.assertRaisesRegex(ValueError, 'only one complete update.json'):
            self.advance()
        self.assertEqual(before, self.fake.files)


if __name__ == '__main__':
    unittest.main()
