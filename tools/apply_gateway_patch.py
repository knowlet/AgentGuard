"""Apply an exact-source, fail-closed webhook decoder patch. Does not deploy it."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from tools.atomic_files import write_set

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
        text = text.replace('#[derive(Debug, Clone, Serialize, Deserialize)]\n' + new,
                            '#[derive(Debug, Clone, Serialize)]\n' + new)
    for action in ('RequestAction', 'ResponseAction'):
        old = '#[derive(Debug, Clone, Serialize, Deserialize)]\n#[serde(untagged, rename_all = "snake_case")]\npub enum ' + action
        new = '#[derive(Debug, Clone, Serialize)]\n#[serde(untagged, rename_all = "snake_case")]\npub enum ' + action
        if text.count(old) != 1:
            raise ValueError('missing exact action patch anchor')
        text = text.replace(old, new)
    # HTTP-level failure cannot be turned into allow by a syntactically valid body.
    anchor = '\tlet parsed = json::from_response_body(res).await?;'
    if text.count(anchor) != 2:
        raise ValueError('missing exact transport patch anchors')
    text = text.replace(anchor, '\tif res.status() != ::http::StatusCode::OK {\n'
                        '\t\treturn Err(anyhow::anyhow!("AG_WIRE_HTTP_STATUS"));\n\t}\n'
                        '\tlet parsed = json::from_response_body(res).await\n'
                        '\t\t.map_err(|_| anyhow::anyhow!("AG_WIRE_INVALID_RESPONSE"))?;')
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
    for name, action in (('GuardrailsPromptResponse', 'RequestAction'),
                         ('GuardrailsResponseResponse', 'ResponseAction')):
        text += """
impl<'de> Deserialize<'de> for ENVELOPE {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireEnvelope { action: ACTION }
        let envelope = agentguard_strict_wire::Object::<WireEnvelope>::deserialize(d)?;
        Ok(Self { action: envelope.0.action })
    }
}
""".replace('ENVELOPE', name).replace('ACTION', action)
    return text.encode('utf-8')


def apply(source: Path, manifest: Path) -> dict:
    source = source.resolve()
    root = subprocess.check_output(['git', '-C', str(source), 'rev-parse', '--show-toplevel'], text=True).strip()
    if Path(root).resolve() != source:
        raise ValueError('UPSTREAM_ROOT_MISMATCH')
    revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    if revision != UPSTREAM_REVISION:
        raise ValueError('UPSTREAM_REVISION_MISMATCH')
    dirty = subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain',
                                     '--untracked-files=normal'], text=True).strip()
    if dirty:
        raise ValueError('UPSTREAM_WORKTREE_NOT_CLEAN')
    target = source / WEBHOOK_PATH
    raw = target.read_bytes()
    output = patched_source(raw)
    decoder = (ROOT / 'patches/agentgateway-v1.5.0/strict_wire.rs').read_bytes()
    destination = target.with_name('agentguard_strict_wire.rs')
    if manifest.resolve() in {target.resolve(), destination.resolve()}:
        raise ValueError('PATCH_OUTPUT_ALIAS')
    if destination.exists():
        raise ValueError('decoder destination already exists')
    report = {'kind': 'agentguard-gateway-patch/v1', 'source_revision': revision,
              'upstream_webhook_git_blob': git_blob(raw),
              'patched_webhook_sha256': hashlib.sha256(output).hexdigest(),
              'decoder_sha256': hashlib.sha256(decoder).hexdigest(),
              'installer_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'wire_profile': 'normalized-text-v1', 'protected_gate': 'NOT_EVALUATED'}
    write_set({destination: decoder, target: output,
               manifest: (json.dumps(report, indent=2) + '\n').encode()})
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
