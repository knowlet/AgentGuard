"""Apply an exact-source, fail-closed webhook decoder patch. Does not deploy it."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM_REVISION = 'fe6732474a96a0363dfb9822859af4e9bab360fa'
WEBHOOK_PATH = 'crates/agentgateway/src/llm/policy/webhook.rs'
WEBHOOK_BLOB = 'b6a9e64f7d541ffecb76eebb384e4308178d0fde'


def git_blob(raw: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def patched_source(raw: bytes) -> bytes:
    if git_blob(raw) != WEBHOOK_BLOB:
        raise ValueError('UPSTREAM_WEBHOOK_MISMATCH: refusing fuzzy or repeated patch')
    text = raw.decode('utf-8')
    for name in ('GuardrailsPromptResponse', 'GuardrailsResponseResponse'):
        old = '#[serde(rename_all = "snake_case")]\npub struct ' + name
        new = '#[serde(rename_all = "snake_case", deny_unknown_fields)]\npub struct ' + name
        if text.count(old) != 1:
            raise ValueError('missing exact envelope patch anchor')
        text = text.replace(old, new)
    for action in ('RequestAction', 'ResponseAction'):
        old = '#[derive(Debug, Clone, Serialize, Deserialize)]\n#[serde(untagged, rename_all = "snake_case")]\npub enum ' + action
        new = '#[derive(Debug, Clone, Serialize)]\n#[serde(untagged, rename_all = "snake_case")]\npub enum ' + action
        if text.count(old) != 1:
            raise ValueError('missing exact action patch anchor')
        text = text.replace(old, new)
    text += '\n#[path = "agentguard_strict_wire.rs"]\nmod agentguard_strict_wire;\n'
    for action, phase in (('RequestAction', 'Request'), ('ResponseAction', 'Response')):
        text += '''
impl<'de> Deserialize<'de> for ACTION {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use agentguard_strict_wire::{Action, Phase};
        match agentguard_strict_wire::decode(d, Phase::PHASE)? {
            Action::Pass { reason } => Ok(Self::Pass(PassAction { reason: Some(reason) })),
            Action::Reject { reason, body, status_code } => Ok(Self::Reject(RejectAction {
                reason: Some(reason), body, status_code,
            })),
            Action::Mask { reason, body } => {
                let value = serde_json::json!({"body": body, "reason": reason});
                let mask = serde_json::from_value::<MaskAction>(value)
                    .map_err(|_| serde::de::Error::custom("AG_WIRE_MASK_CONVERSION"))?;
                Ok(Self::Mask(mask))
            }
        }
    }
}
'''.replace('ACTION', action).replace('PHASE', phase)
    return text.encode('utf-8')


def apply(source: Path, manifest: Path) -> dict:
    revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    if revision != UPSTREAM_REVISION:
        raise ValueError('UPSTREAM_REVISION_MISMATCH')
    target = source / WEBHOOK_PATH
    raw = target.read_bytes()
    output = patched_source(raw)
    decoder = (ROOT / 'patches/agentgateway-v1.5.0/strict_wire.rs').read_bytes()
    destination = target.with_name('agentguard_strict_wire.rs')
    if destination.exists():
        raise ValueError('decoder destination already exists')
    # All validations precede writes. Only this disposable upstream checkout is modified.
    destination.write_bytes(decoder)
    target.write_bytes(output)
    report = {'kind': 'agentguard-gateway-patch/v1', 'source_revision': revision,
              'upstream_webhook_git_blob': git_blob(raw),
              'patched_webhook_sha256': hashlib.sha256(output).hexdigest(),
              'decoder_sha256': hashlib.sha256(decoder).hexdigest(),
              'installer_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'wire_profile': 'normalized-text-v1', 'protected_gate': 'NOT_EVALUATED'}
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--manifest', type=Path, required=True)
    args = p.parse_args()
    try:
        print(json.dumps(apply(args.source, args.manifest), indent=2))
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        p.exit(2, f'{exc}\n')

if __name__ == '__main__':
    main()
