"""Build profile invariants for the Linux upstream application."""
from pathlib import Path
import unittest

class BuildContract(unittest.TestCase):
    def test_allocator_feature_is_not_disabled(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/p0-patched.yml').read_text()
        self.assertNotIn('--no-default-features', workflow)
        self.assertIn('cargo build --locked -p agentgateway-app --bin agentgateway', workflow)

    def test_patch_artifact_includes_new_decoder(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/p0-patched.yml').read_text()
        self.assertIn('git -C "$RUNNER_TEMP/upstream" add -N crates/agentgateway/src/llm/policy/agentguard_strict_wire.rs', workflow)
