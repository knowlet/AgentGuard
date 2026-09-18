"""Guard against reintroducing contradictory copies of the policy example."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DocumentationContract(unittest.TestCase):
    def test_policy_has_explicit_digest_and_time_requirements(self):
        text = (ROOT / 'examples/policies/strict-local.proposed.yaml').read_text()
        for requirement in ('mode: external_digest_bound',
                            'bindTo: [gateway_image, gateway_config, compiler, adapter]',
                            'rejectFutureDated: true', 'rejectExpired: true',
                            'rejectDigestMismatch: true', 'requireTrustedProvenance: true'):
            with self.subTest(requirement=requirement):
                self.assertIn(requirement, text)

    def test_protocol_has_one_canonical_policy_source(self):
        text = (ROOT / 'docs/protocol-contracts.md').read_text()
        self.assertIn('../examples/policies/strict-local.proposed.yaml', text)
        self.assertNotIn('```yaml', text)
        self.assertNotIn('external_per_version', text)


if __name__ == '__main__':
    unittest.main()
