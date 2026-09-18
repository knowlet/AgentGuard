"""Apply the strict action parser only to the audited AgentGateway source blob.

This patches the Gateway itself. It is not a webhook proxy or a replacement
serializer. Reapplying or applying to a changed upstream tree is an error.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SOURCE_REVISION = 'fe6732474a96a0363dfb9822859af4e9bab360fa'
WEBHOOK = Path('crates/agentgateway/src/llm/policy/webhook.rs')
WEBHOOK_BLOB = 'b6a9e64f7d541ffecb76eebb384e4308178d0fde'
MODULE = ROOT / 'patches/agentgateway/strict_action.rs'
FIXTURES = ROOT / 'tests/fixtures/webhook-negative.json'


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def patched_source(raw: bytes) -> bytes:
    git_hash = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    if git_hash != WEBHOOK_BLOB:
        raise ValueError('UPSTREAM_SOURCE_MISMATCH: refusing unreviewed or already patched source')
    text = raw.decode('utf-8')
    for kind, name in [('struct', 'GuardrailsPromptResponse'), ('struct', 'GuardrailsResponseResponse'),
                       ('enum', 'RequestAction'), ('enum', 'ResponseAction')]:
        pattern = (r'#\[derive\(Debug, Clone, Serialize, Deserialize\)\]'
                   r'(\n#\[serde\([^\n]+\)\]\npub ' + kind + ' ' + name + r' \{)')
        text, n = re.subn(pattern, r'#[derive(Debug, Clone, Serialize)]\1', text)
        if n != 1:
            raise ValueError('PATCH_ANCHOR_MISMATCH: ' + name)
    return ('mod strict_action;\n\n' + text).encode()


def apply(upstream: Path) -> dict:
    source = upstream / WEBHOOK
    raw = source.read_bytes()
    patched = patched_source(raw)
    destination = source.parent / 'webhook'
    destination.mkdir(exist_ok=True)
    module_bytes, fixtures = MODULE.read_bytes(), FIXTURES.read_bytes()
    (destination / 'strict_action.rs').write_bytes(module_bytes)
    (destination / 'agentguard-webhook-negative.json').write_bytes(fixtures)
    source.write_bytes(patched)
    return {'kind': 'agentguard-gateway-patch/v1', 'upstream_revision': SOURCE_REVISION,
            'upstream_webhook_blob': WEBHOOK_BLOB, 'upstream_webhook_sha256': sha256(raw),
            'patched_webhook_sha256': sha256(patched), 'module_sha256': sha256(module_bytes),
            'patcher_sha256': sha256(Path(__file__).read_bytes()), 'fixtures_sha256': sha256(fixtures)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = apply(args.upstream)
    except (ValueError, OSError) as exc:
        parser.exit(2, str(exc) + '\n')
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
