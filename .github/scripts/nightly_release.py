#!/usr/bin/env python3
# Copyright 2026 Duck Apps Contributor
# If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
# SPDX-License-Identifier: Apache-2.0
"""Prepare a unique Nightly draft or publish its verified, complete asset set."""
import argparse
import hashlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def gh(*args, missing_ok=False):
    result = subprocess.run(['gh', *args], capture_output=True, text=True)
    if result.returncode:
        if missing_ok and '(HTTP 404)' in result.stderr:
            return None
        raise RuntimeError(result.stderr.strip() or 'GitHub request failed')
    return json.loads(result.stdout) if args[0] == 'api' and result.stdout.strip() else None


def find_release(repo, tag):
    release = gh('api', f'repos/{repo}/releases/tags/{tag}', missing_ok=True)
    if release is not None:
        return release
    # The by-tag endpoint omits drafts. Draft retries must locate the existing release.
    pages = gh('api', '--paginate', '--slurp', f'repos/{repo}/releases?per_page=100')
    matches = [item for page in pages for item in page if item.get('tag_name') == tag]
    if len(matches) > 1:
        raise ValueError('Multiple releases use the same archive tag')
    return matches[0] if matches else None


def require_channel(repo, allow_incomplete=False):
    release = gh('api', f'repos/{repo}/releases/tags/update', missing_ok=True)
    if (release is None or release.get('tag_name') != 'update' or release.get('draft') is not False
            or release.get('immutable') is not False or release.get('prerelease') is not True):
        raise ValueError('An existing public, mutable update prerelease is required; never recreate or republish it')
    release_id = release.get('id')
    if type(release_id) is not int or release_id <= 0:
        raise ValueError('The channel release ID is missing')
    pages = gh('api', '--paginate', '--slurp', f'repos/{repo}/releases/{release_id}/assets?per_page=100')
    release['assets'] = [asset for page in pages for asset in page]
    assets = release['assets']
    if len(assets) > 1 or any(asset.get('name') != 'update.json' for asset in assets):
        raise ValueError('The update release may contain only one complete update.json')
    complete = len(assets) == 1 and assets[0].get('state') == 'uploaded' and assets[0].get('size', 0) > 0
    if not complete and not (allow_incomplete and (not assets or assets[0].get('state') == 'starter')):
        raise ValueError('The update release has no complete update.json')
    return release


def require_immutable(release):
    if release.get('draft') is not False or release.get('immutable') is not True:
        raise ValueError('The published archive must be immutable; enable repository release immutability')


def safe_name(name):
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9._+-]+', name):
        raise ValueError('Unsafe release asset filename')
    return name


def canonical_asset_url(repo, tag, name):
    safe_name(name)
    return f'https://github.com/{repo}/releases/download/{tag}/{name}'


def require_public_urls(release, repo, tag):
    for asset in release.get('assets', []):
        expected = f'https://github.com/{repo}/releases/download/{tag}/{asset["name"]}'
        if asset.get('browser_download_url') != expected:
            raise ValueError('Published archive asset URL does not match its permanent tag')


def nightly_tag(timestamp, sha):
    if not re.fullmatch('[0-9a-f]{40}', sha):
        raise ValueError('A complete lowercase commit SHA is required')
    instant = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    if instant.utcoffset() is None:
        raise ValueError('The build timestamp must include its timezone')
    return f"nightly-{instant.astimezone(timezone.utc):%Y-%m-%d}-{sha[:8]}"


def validate_tag(tag, sha):
    match = re.fullmatch(r'nightly-(\d{4}-\d{2}-\d{2})-([0-9a-f]{8})', tag)
    if not match or match[2] != sha[:8] or not re.fullmatch('[0-9a-f]{40}', sha):
        raise ValueError('Nightly tag does not identify the expected commit')
    datetime.strptime(match[1], '%Y-%m-%d')


def verify_ref(repo, tag, sha):
    ref = gh('api', f'repos/{repo}/git/ref/tags/{tag}', missing_ok=True)
    if ref is None:
        gh('api', '-X', 'POST', f'repos/{repo}/git/refs', '-f', f'ref=refs/tags/{tag}', '-f', f'sha={sha}')
        return
    obj = ref['object']
    for _ in range(4):
        if obj['type'] == 'commit':
            if obj['sha'] != sha:
                raise ValueError('Existing Nightly tag points at another commit')
            return
        if obj['type'] != 'tag':
            break
        obj = gh('api', f'repos/{repo}/git/tags/{obj["sha"]}')['object']
    raise ValueError('Nightly tag does not resolve to a commit')


def require_complete(release, tag):
    if release.get('tag_name') != tag or release.get('prerelease') is not True:
        raise ValueError('Unexpected Nightly release identity or type')
    assets = release.get('assets', [])
    names = [item.get('name', '') for item in assets]
    if (len(assets) != 3 or names.count('update.json') != 1
            or sum(name.endswith('.apk') for name in names) != 1
            or sum(name.endswith('.aar') for name in names) != 1
            or any(item.get('state') != 'uploaded' or item.get('size', 0) <= 0 for item in assets)):
        raise ValueError('Nightly must contain exactly one complete APK, AAR and update.json')


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def check_file(path, asset):
    if path.stat().st_size != asset['sizeBytes'] or digest(path) != asset['sha256']:
        raise ValueError(f'Asset differs from its archive manifest: {path.name}')


def validate_manifest(manifest, repo, tag, sha):
    validate_tag(tag, sha)
    if (type(manifest.get('schemaVersion')) is not int or manifest['schemaVersion'] != 1 or manifest.get('channel') != 'nightly'
            or manifest.get('branch') not in ['master', 'main'] or manifest.get('commit', {}).get('sha') != sha
            or manifest.get('releaseTag') != tag):
        raise ValueError('Archive manifest identifies another build')
    version = manifest.get('versionCode')
    if not isinstance(manifest.get('versionName'), str) or not manifest['versionName'].strip():
        raise ValueError('Archive version name is missing')
    if type(version) is not int or version <= 0:
        raise ValueError('Invalid archive version code')
    timestamp = datetime.fromisoformat(manifest['builtAtUtc'].replace('Z', '+00:00'))
    if timestamp.utcoffset() is None or timestamp.astimezone(timezone.utc).strftime('%Y-%m-%d') != tag[8:18]:
        raise ValueError('Archive tag and build date differ')
    for key, suffix in [('apk', '.apk'), ('sdk', '.aar')]:
        asset = manifest[key]
        name = safe_name(asset['name'])
        if (not name.endswith(suffix) or type(asset.get('sizeBytes')) is not int or asset['sizeBytes'] <= 0
                or not re.fullmatch('[0-9a-f]{64}', asset.get('sha256', ''))
                or asset.get('downloadUrl') != f'https://github.com/{repo}/releases/download/{tag}/{name}'):
            raise ValueError('Archive asset metadata is invalid')
    if manifest['apk']['sizeBytes'] > 256 * 1024 * 1024:
        raise ValueError('APK exceeds the independent download cap')


def download_asset(repo, asset_id, path):
    # Asset IDs and the documented binary API remain usable while a draft's browser URL changes.
    with path.open('wb') as output:
        subprocess.run(['gh', 'api', '-H', 'Accept: application/octet-stream',
                        f'repos/{repo}/releases/assets/{asset_id}'], stdout=output, check=True)


def verify_draft(repo, sha, tag, release_id, expected_ids, manifest_path, apk_path, aar_path):
    validate_tag(tag, sha)
    verify_ref(repo, tag, sha)
    release = gh('api', f'repos/{repo}/releases/{release_id}')
    pages = gh('api', '--paginate', '--slurp', f'repos/{repo}/releases/{release_id}/assets?per_page=100')
    release['assets'] = [asset for page in pages for asset in page]
    require_complete(release, tag)
    actual_ids = [asset.get('id') for asset in release['assets']]
    if (release.get('id') != release_id or release.get('draft') is not True
            or len(expected_ids) != 3 or len(set(expected_ids)) != 3
            or any(type(item) is not int or item <= 0 for item in expected_ids + actual_ids)
            or set(actual_ids) != set(expected_ids)):
        raise ValueError('Draft release or asset IDs differ from the upload results')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    validate_manifest(manifest, repo, tag, sha)
    metadata = [manifest['apk'], manifest['sdk'], {
        'name': 'update.json', 'sizeBytes': manifest_path.stat().st_size, 'sha256': digest(manifest_path),
    }]
    files = [apk_path, aar_path, manifest_path]
    assets = {asset['name']: asset for asset in release['assets']}
    with tempfile.TemporaryDirectory(prefix='nightly-draft-') as directory:
        for expected, local in zip(metadata, files):
            if local.name != expected['name']:
                raise ValueError('Staged filename differs from the generated manifest')
            check_file(local, expected)
            asset = assets.get(expected['name'])
            if (asset is None or asset.get('size') != expected['sizeBytes']
                    or (asset.get('digest') is not None and asset['digest'].lower() != 'sha256:' + expected['sha256'])):
                raise ValueError('Draft asset metadata differs from the staged file')
            downloaded = Path(directory) / safe_name(expected['name'])
            download_asset(repo, asset['id'], downloaded)
            check_file(downloaded, expected)


def prepare(repo, sha, timestamp):
    tag = nightly_tag(timestamp, sha)
    require_channel(repo, allow_incomplete=True)
    verify_ref(repo, tag, sha)
    release = find_release(repo, tag)
    if release is not None:
        if release.get('draft') is False:
            require_complete(release, tag)
            require_immutable(release)
            require_public_urls(release, repo, tag)
            return tag, False
        if release.get('draft') is not True:
            raise ValueError('Release did not report its draft state')
        # Only unpublished attempts may be rebuilt. Never delete the tag or a public release.
        gh('release', 'delete', tag, '--yes', '--repo', repo)
    return tag, True


def publish(repo, sha, tag):
    validate_tag(tag, sha)
    verify_ref(repo, tag, sha)
    release = find_release(repo, tag)
    if release is None:
        raise ValueError('The archive draft is missing')
    require_complete(release, tag)
    if release.get('draft') is not True:
        raise ValueError('Only a verified draft may be published')
    gh('release', 'edit', tag, '--draft=false', '--prerelease', '--latest=false', '--repo', repo)
    published = gh('api', f'repos/{repo}/releases/tags/{tag}')
    require_complete(published, tag)
    require_immutable(published)
    require_public_urls(published, repo, tag)
    verify_ref(repo, tag, sha)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['prepare', 'verify', 'publish'])
    operation = parser.parse_args().operation
    repo, sha = os.environ['GITHUB_REPOSITORY'], os.environ['GITHUB_SHA']
    if operation == 'verify':
        if os.environ['APK_RELEASE_ID'] != os.environ['MANIFEST_RELEASE_ID']:
            raise ValueError('Binaries and manifest were uploaded to different releases')
        uploaded = json.loads(os.environ['MANIFEST_ASSETS_JSON'])
        if len(uploaded) != 1 or uploaded[0].get('name') != 'update.json':
            raise ValueError('Unexpected manifest upload result')
        verify_draft(repo, sha, os.environ['NIGHTLY_TAG'], int(os.environ['APK_RELEASE_ID']),
                     [int(os.environ['APK_ASSET_ID']), int(os.environ['AAR_ASSET_ID']), uploaded[0]['id']],
                     Path(os.environ['MANIFEST_PATH']), Path(os.environ['APK_PATH']), Path(os.environ['AAR_PATH']))
    elif operation == 'publish':
        publish(repo, sha, os.environ['NIGHTLY_TAG'])
    else:
        tag, should_publish = prepare(repo, sha, os.environ['BUILD_TIME_ISO'])
        with Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='utf-8') as output:
            output.write(f'tag={tag}\npublish={str(should_publish).lower()}\n')


if __name__ == '__main__':
    main()
