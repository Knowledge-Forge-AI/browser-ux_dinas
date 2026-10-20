"""Validate retained synthetic evidence, never substitute for native replay."""
import base64
import hashlib
import json
from pathlib import Path

import pytest


FIXTURE = Path(__file__).parent / 'fixtures/cnt-native/firefox/6.12.1'


def validate(metadata, artifacts, images):
    expected_harnesses = {"cnt-native-firefox-ui.py", "cnt-native-firefox-ui.js"}
    assert set(metadata["harness_sha256"]) == expected_harnesses
    for name in expected_harnesses:
        # R1 evidence stays bound to the exact original bytes, not the R2
        # refusal entrypoint. Historical text is never selected for execution.
        historical = Path(__file__).parent / 'fixtures/cnt-native/history/r1' / (name + '.txt')
        actual = hashlib.sha256(historical.read_bytes()).hexdigest()
        assert actual == metadata["harness_sha256"][name], f"Harness drift: {name}"
    assert metadata['synthetic_only'] is True
    assert (metadata['engine'], metadata['version'], metadata['extension_id'], metadata['manifest_version']) == (
        'firefox', '6.12.1', 'clear-new-tab@loftyshaky', 3)
    assert metadata['acceptance'] == 'NOT_CHARACTERIZED'
    for label, raw in artifacts.items():
        assert hashlib.sha256(raw).hexdigest() == metadata['native_artifacts'][label]['sha256']
    assert artifacts['export'] == artifacts['reexport']
    backup = json.loads(artifacts['export'])
    chunks = backup['chunks']
    assert len(chunks) == 4
    assert [c['file']['name'] for c in chunks] == [f'synthetic-{i}.png' for i in range(4)]
    assert len({c['data']['id'] for c in chunks}) == 4
    assert [int(c['data']['i']) for c in chunks] == [1, 2, 3, 4]
    for i, chunk in enumerate(chunks):
        data = base64.b64decode(chunk['file']['background'].split(',', 1)[1], validate=True)
        assert data == images[i]
        assert hashlib.sha256(data).hexdigest() == metadata['content_sha256'][i]
        assert chunk['file']['last_modified'] == 1700000000000 + i
        assert chunk['tasks'] == []  # Evidence limit, not absence of task support.
    assert len(set(images)) == 3 and images[0] == images[3]
    assert backup['settings']['prefs']['background_size'] == 'cover_screen'
    assert backup['custom_code'] == {'html': '<p>Synthetic CNT fixture</p>',
                                    'css': 'p { color: rgb(12,34,56); }', 'js': 'void 0;'}


def inputs():
    metadata = json.loads((FIXTURE / 'metadata.json').read_text())
    artifacts = {label: (FIXTURE / (label + '.json')).read_bytes() for label in ('export', 'reexport')}
    images = [(FIXTURE / f'image-{i}.png').read_bytes() for i in range(4)]
    return metadata, artifacts, images


def test_native_subset_fixture():
    validate(*inputs())


@pytest.mark.parametrize('mutation', ['artifact', 'engine', 'order', 'content', 'harness', 'missing_harness'])
def test_fixture_rejects_drift(mutation):
    metadata, artifacts, images = inputs()
    if mutation == 'harness':
        metadata['harness_sha256']['cnt-native-firefox-ui.py'] = '0' * 64
    elif mutation == 'missing_harness':
        del metadata['harness_sha256']['cnt-native-firefox-ui.js']
    elif mutation == 'artifact':
        artifacts['export'] += b' '
    elif mutation == 'engine':
        metadata['engine'] = 'chrome'
    elif mutation == 'content':
        images[0] = b'changed'
    else:
        parsed = json.loads(artifacts['export'])
        parsed['chunks'].reverse()
        # Even a refreshed digest cannot hide occurrence/order loss.
        for label in artifacts:
            artifacts[label] = json.dumps(parsed).encode()
            metadata['native_artifacts'][label]['sha256'] = hashlib.sha256(artifacts[label]).hexdigest()
    with pytest.raises(AssertionError):
        validate(metadata, artifacts, images)
