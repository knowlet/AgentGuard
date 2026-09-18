"""Exercise the real workflow's active literal run block, not just bash itself."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / '.github/workflows/p0-patched.yml'


def literal_run_blocks(text):
    # This workflow intentionally uses only literal run blocks and literal bash.
    # An unsupported YAML form fails this contract rather than being guessed.
    lines = text.splitlines()
    scripts = []
    for i, line in enumerate(lines):
        if re.fullmatch(r'\s+run: \|', line):
            indent = len(line) - len(line.lstrip())
            body = []
            for next_line in lines[i+1:]:
                if next_line.strip() and len(next_line) - len(next_line.lstrip()) <= indent:
                    break
                body.append(next_line[indent+2:])
            scripts.append('\n'.join(body))
    return scripts


def assert_shell_contract(text):
    if not re.search(r'^defaults:\n  run:\n    shell: bash\n', text, flags=re.M):
        raise ValueError('WORKFLOW_BASH_DEFAULT_MISSING')
    if any(m.group(1) != 'bash' for m in re.finditer(r'^\s+shell: (.+)$', text, flags=re.M)):
        raise ValueError('WORKFLOW_UNVERIFIED_SHELL_OVERRIDE')
    scripts = literal_run_blocks(text)
    if not scripts or any(not s.startswith('set -euo pipefail\n') for s in scripts):
        raise ValueError('WORKFLOW_PIPEFAIL_MISSING')
    return scripts


class WorkflowShell(unittest.TestCase):
    def test_active_workflow_script_propagates_failure_past_tee(self):
        scripts = assert_shell_contract(WORKFLOW.read_text())
        script, = [s for s in scripts if 'python3 -m unittest discover' in s]
        with tempfile.TemporaryDirectory() as t:
            # Substitute only the executable through PATH. Execute the actual
            # saved workflow script verbatim, including its explicit shell flags.
            root = Path(t); fake = root / 'python3'; fake.write_text('#!/bin/sh\nexit 7\n'); fake.chmod(0o700)
            env = dict(os.environ, PATH=str(root) + ':' + os.environ['PATH'])
            result = subprocess.run(['bash', '-c', script], cwd=root, env=env, capture_output=True)
            self.assertEqual(result.returncode, 7)
            self.assertFalse((root / 'reports/source.zip').exists())

    def test_removing_bash_or_pipefail_fails_contract(self):
        text = WORKFLOW.read_text()
        for altered in (text.replace('    shell: bash\n', ''), text.replace('set -euo pipefail', 'set -eu'),
                        text + '\n# defaults:\n#   run:\n#     shell: bash\n      shell: sh\n'):
            with self.assertRaises(ValueError): assert_shell_contract(altered)
