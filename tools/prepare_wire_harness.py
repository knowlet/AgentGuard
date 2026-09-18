"""Compile the exact patched action types with small normalized-type stand-ins.

Fast serde contract test only. Real-Gateway acceptance remains a separate job.
The dependency versions/checksums come from the pinned upstream Cargo.lock.
"""
from pathlib import Path
import argparse
import json
import shutil
import tomllib
from tools.apply_gateway_patch import ROOT, WEBHOOK_PATH


def prepare(source: Path, out: Path):
    text = (source / WEBHOOK_PATH).read_text()
    start = text.index('#[derive(Debug, Clone, Serialize, Deserialize)]\n#[serde(rename_all = "snake_case")]\npub struct GuardrailsPromptRequest')
    end = text.index('fn build_request_for_request(')
    addon = text[text.index('#[path = "agentguard_strict_wire.rs"]'):]
    out.mkdir(parents=True, exist_ok=True)
    (out / 'src').mkdir(exist_ok=True)
    prelude = '''use serde::{Serialize, Deserialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message { pub role: String, pub content: String }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseChoice { pub message: Message }
'''
    test = '''
#[cfg(test)] mod fixture_tests {
 use super::*;
 #[test] fn all_negative_fixtures_hit_actual_patched_types() {
  let cases: serde_json::Value = serde_json::from_str(include_str!("../negative.json")).unwrap();
  for c in cases["cases"].as_array().unwrap() {
   for phase in c["phases"].as_array().unwrap() {
    let raw = c["raw"].as_str().unwrap();
    let failed = if phase == "request" {
     serde_json::from_str::<GuardrailsPromptResponse>(raw).is_err()
    } else { serde_json::from_str::<GuardrailsResponseResponse>(raw).is_err() };
    assert!(failed, "{} {}", c["id"], phase);
   }
  }
 }
}
'''
    (out / 'src/lib.rs').write_text(prelude + text[start:end] + addon + test)
    shutil.copyfile(source / WEBHOOK_PATH.replace('webhook.rs', 'agentguard_strict_wire.rs'), out / 'src/agentguard_strict_wire.rs')
    shutil.copyfile(ROOT / 'tests/fixtures/webhook-negative.json', out / 'negative.json')
    packages = tomllib.loads((source / 'Cargo.lock').read_text())['package']
    versions = {name: next(x['version'] for x in packages if x['name'] == name) for name in ('serde', 'serde_json')}
    (out / 'Cargo.toml').write_text('[package]\nname="agentguard-wire-contract"\nversion="0.0.0"\nedition="2021"\n[dependencies]\n'
        + 'serde = { version="=' + versions['serde'] + '", features=["derive"] }\n'
        + 'serde_json = "=' + versions['serde_json'] + '"\n')
    # Reuse resolved upstream packages; Cargo removes unused packages in the small lockfile.
    shutil.copyfile(source / 'Cargo.lock', out / 'Cargo.lock')
    print(json.dumps({'harness': str(out), 'scope': 'SERDE_CONTRACT_NOT_GATEWAY', 'versions': versions}))

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    prepare(a.source, a.output)
