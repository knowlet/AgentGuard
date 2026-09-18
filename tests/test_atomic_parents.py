"""No-follow parent traversal regressions using actual filesystem objects."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tools.atomic_files import write_set


class AtomicParents(unittest.TestCase):
    def test_ancestor_symlinks_are_rejected_before_any_write(self):
        for relative in ('redirect/out', 'redirect/deep/new/out'):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as t:
                root = Path(t); external = root / 'outside'; external.mkdir()
                (root / 'redirect').symlink_to(external, target_is_directory=True)
                safe = root / 'safe'; safe.write_bytes(b'original')
                with self.assertRaisesRegex(ValueError, 'PARENT_NOT_DIRECTORY_OR_SYMLINK'):
                    write_set({safe: b'changed', root / relative: b'forbidden'})
                self.assertEqual(safe.read_bytes(), b'original')
                self.assertEqual(list(external.iterdir()), [])
                self.assertFalse(list(root.rglob('.agentguard-*')))

    def test_dangling_symlink_parent_and_leaf_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); link = root / 'link'; link.symlink_to(root / 'missing')
            for target in (link, link / 'out'):
                with self.assertRaises(ValueError): write_set({target: b'bad'})
            self.assertFalse((root / 'missing').exists())

    def test_new_parents_work_without_symlinks(self):
        with tempfile.TemporaryDirectory() as t:
            target = Path(t) / 'a/b/c'
            write_set({target: b'value'})
            self.assertEqual(target.read_bytes(), b'value')

    def test_replacement_uses_directory_descriptors(self):
        with tempfile.TemporaryDirectory() as t:
            target = Path(t) / 'out'; real = os.replace
            with patch('tools.atomic_files.os.replace', wraps=real) as replace:
                write_set({target: b'value'})
            args = replace.call_args
            self.assertEqual(args.args[1], 'out')
            self.assertIsInstance(args.kwargs['src_dir_fd'], int)
            self.assertEqual(args.kwargs['src_dir_fd'], args.kwargs['dst_dir_fd'])

    def test_dotdot_alias_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            with self.assertRaisesRegex(ValueError, 'ALIAS'):
                write_set({root / 'a/../out': b'bad'})
