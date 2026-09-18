"""Regression coverage consolidated from PR #7 and #8. Synthetic rows are unit-only."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from email.message import Message
from unittest.mock import Mock, patch
from tools import apply_gateway_patch as patcher
from tools import atomic_files, gateway_acceptance as accept
from tools.process_identity import listener_owned, wait_listener
from agentguard.context import HEADER_EXPRESSIONS, decide, validate_config, validate_route
from test_gateway_patch import passing_observations, rejection


def tiny_upstream():
    text = ''
    for name in ('GuardrailsPromptResponse','GuardrailsResponseResponse'):
        text += '#[derive(Debug, Clone, Serialize, Deserialize)]\n#[serde(rename_all = "snake_case")]\npub struct ' + name + ' {}\n'
    for name in ('RequestAction','ResponseAction'):
        text += '#[derive(Debug, Clone, Serialize, Deserialize)]\n#[serde(untagged, rename_all = "snake_case")]\npub enum ' + name + ' {}\n'
    for name in ('send_request','send_response'):
        text += 'fn ' + name + '() {\n\tlet parsed = json::from_response_body(res).await?;\n}\n'
    return text.encode()


class PatchTransaction(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.source = Path(self.tmp.name) / 'source'; self.source.mkdir()
        self.target = self.source / patcher.WEBHOOK_PATH; self.target.parent.mkdir(parents=True)
        self.raw = tiny_upstream(); self.target.write_bytes(self.raw)
        self.decoder = self.target.with_name('agentguard_strict_wire.rs')
        self.manifest = Path(self.tmp.name) / 'manifest.json'; self.manifest.write_bytes(b'old-manifest')
        def git(*args):
            return subprocess.check_output(['git','-C',str(self.source),*args], text=True).strip()
        git('init','-q'); git('add','.')
        git('-c','user.name=Unit Test','-c','user.email=test@example.invalid','commit','-qm','fixture')
        self.revision = git('rev-parse','HEAD')
        for name, value in [('UPSTREAM_REVISION',self.revision), ('WEBHOOK_BLOB',patcher.git_blob(self.raw))]:
            ctx = patch.object(patcher,name,value); ctx.start(); self.addCleanup(ctx.stop)

    def assert_unchanged(self):
        self.assertEqual(self.target.read_bytes(), self.raw)
        self.assertEqual(self.manifest.read_bytes(), b'old-manifest')
        self.assertFalse(self.decoder.exists())
        self.assertEqual(list(Path(self.tmp.name).rglob('.agentguard-*')), [])

    def test_each_failed_output_rolls_back_earlier_files(self):
        real = os.replace
        for target in (self.decoder, self.target, self.manifest):
            with self.subTest(target=target):
                failed = False
                def injected(src, dst, **kwargs):
                    nonlocal failed
                    # Compare directory identity by dev/inode: a /proc readlink
                    # string is kernel-canonicalized, so it never matches a path
                    # built under a symlinked TMPDIR, and /proc is Linux-only.
                    if 'dst_dir_fd' in kwargs:
                        dst_stat = os.fstat(kwargs['dst_dir_fd'])
                        wanted = os.stat(target.parent)
                        actual = ((dst_stat.st_dev, dst_stat.st_ino) == (wanted.st_dev, wanted.st_ino)
                                  and dst == target.name)
                    else:
                        actual = Path(dst) == target
                    if actual and not failed:
                        failed = True
                        raise OSError('injected write failure')
                    return real(src,dst,**kwargs)
                with patch.object(atomic_files.os, 'replace', side_effect=injected):
                    with self.assertRaises(OSError): patcher.apply(self.source,self.manifest)
                self.assert_unchanged()

    def test_flagged_index_entry_is_rejected_before_patching(self):
        def git(*args):
            return subprocess.check_output(['git', '-C', str(self.source), *args], text=True).strip()
        for flag in ('--assume-unchanged', '--skip-worktree'):
            with self.subTest(flag=flag):
                git('update-index', flag, patcher.WEBHOOK_PATH)
                # Unmodified content, but Git is told not to re-check this entry.
                self.assertEqual(git('status', '--porcelain'), '')
                with self.assertRaisesRegex(ValueError, 'INDEX_FLAG'):
                    patcher.apply(self.source, self.manifest)
                self.assert_unchanged()
                git('update-index', '--no-' + flag[2:], patcher.WEBHOOK_PATH)

    def test_success_generates_both_status_checks_and_is_not_reapplicable(self):
        patcher.apply(self.source,self.manifest)
        output = self.target.read_text()
        self.assertEqual(output.count('res.status() != ::http::StatusCode::OK'), 2)
        for name in ('send_request','send_response'):
            body = output.split('fn '+name,1)[1].split('\n}',1)[0]
            self.assertIn('AG_WIRE_HTTP_STATUS',body)
        before = self.target.read_bytes()
        with self.assertRaises(ValueError): patcher.apply(self.source,self.manifest)
        self.assertEqual(self.target.read_bytes(), before)

    def test_wrong_revision_leaves_files_untouched(self):
        with patch.object(patcher,'UPSTREAM_REVISION','0'*40):
            with self.assertRaisesRegex(ValueError,'REVISION'): patcher.apply(self.source,self.manifest)
        self.assert_unchanged()

    def test_dependency_drift_leaves_files_untouched(self):
        (self.source / 'Cargo.lock').write_text('changed dependency')
        with self.assertRaisesRegex(ValueError,'NOT_CLEAN'): patcher.apply(self.source,self.manifest)
        self.assert_unchanged()

    def test_manifest_alias_cannot_overwrite_source(self):
        with self.assertRaisesRegex(ValueError,'OUTPUT_ALIAS'): patcher.apply(self.source,self.target)
        self.assert_unchanged()


class AcceptanceReview(unittest.TestCase):
    def test_only_503_and_correct_classification_accept_malformed(self):
        for code in (400,401,403,500,502,504,True):
            row = rejection('request'); row['http_status'] = code
            self.assertFalse(accept.strict_rejection(row))
        for reason in (None,'GENERIC_FAILURE','AG_WIRE_HTTP_STATUS'):
            row = rejection('response'); row['gateway_error_code'] = reason
            self.assertFalse(accept.strict_rejection(row))
        self.assertTrue(accept.strict_rejection(rejection('request')))

    def test_missing_listener_evidence_rejects(self):
        row = rejection('request'); del row['process_listener_owned']
        self.assertFalse(accept.strict_rejection(row))

    def test_shrunk_or_replaced_suite_is_not_its_own_oracle(self):
        c,r,f = passing_observations()
        self.assertEqual(accept.acceptance_status(c,r[:-2],f,accept.negative_cases()[:-1]),'FAIL')
        with patch.object(accept,'EXTRA_ACTIONS',accept.EXTRA_ACTIONS[:-1]):
            with self.assertRaisesRegex(ValueError,'SUITE_CHANGED'): accept.negative_cases()

    def test_fault_without_recovery_cannot_pass(self):
        c,r,f = passing_observations(); f[0].pop('recovery')
        self.assertEqual(accept.acceptance_status(c,r,f),'FAIL')

    def test_quick_error_is_not_a_timeout(self):
        row = dict(rejection('request'),id='timeout',elapsed_ms=5)
        self.assertFalse(accept.fault_rejection(row))

    def test_run_writes_real_report_with_non_wire_gates_unevaluated(self):
        controls, _, _ = passing_observations()
        def observe(proc,exe,port,log,url,state,phase,action,raw=''):
            if action in ('allow','deny','mask'):
                return copy.deepcopy(next(c for c in controls if c['id']==phase+'_'+action))
            row = rejection(phase)
            if action=='http_error': row['gateway_error_code']='AG_WIRE_HTTP_STATUS'
            if action=='timeout': row['elapsed_ms']=10001
            return row
        with tempfile.TemporaryDirectory() as t, patch.dict(os.environ,{'BUILD_MANIFEST_SHA256':'1'*64}), redirect_stdout(io.StringIO()):
            out = Path(t)/'result.json'
            with patch.object(accept,'verify_build',return_value=(b'unit-only-not-a-binary',{'kind':'SYNTHETIC_UNIT_INPUT'})), \
                 patch.object(accept.subprocess,'Popen'), patch.object(accept,'wait_listener'), \
                 patch.object(accept,'observed_call',side_effect=observe):
                self.assertEqual(accept.run(Path(t)/'binary',Path(t)/'manifest',out),0)
            report = json.loads(out.read_text())
            self.assertEqual(report['protected_wire_gate'],'PASS')
            self.assertEqual(report['p0_release_gate'],'NOT_EVALUATED')
            self.assertEqual(report['asr_fpr'],'NOT_EVALUATED')
            self.assertEqual(set(report['gates'].values()),{'NOT_EVALUATED'})
            self.assertFalse(report['deployment_approved'])
            self.assertEqual(len(report['negative_cases']),84)

    def test_cli_failure_never_emits_success(self):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t)/'result.json'
            result = subprocess.run([sys.executable,'-m','tools.gateway_acceptance','--gateway-bin',t+'/absent',
                                     '--build-manifest',t+'/absent-manifest','--report',str(out)],capture_output=True)
            self.assertEqual(result.returncode,2)
            self.assertEqual(json.loads(out.read_text())['protected_wire_gate'],'ERROR')

    def test_manifest_must_match_separately_supplied_reference_and_suite(self):
        from tools.apply_gateway_patch import ROOT, UPSTREAM_REVISION, WEBHOOK_BLOB
        with tempfile.TemporaryDirectory() as t:
            exe=Path(t)/'binary'; exe.write_bytes(b'unit-fixture-not-executed')
            m=Path(t)/'manifest'
            info={'kind':'agentguard-gateway-patch/v1','source_revision':UPSTREAM_REVISION,'upstream_webhook_git_blob':WEBHOOK_BLOB,
                  'decoder_sha256':hashlib.sha256((ROOT/'patches/agentgateway-v1.5.0/strict_wire.rs').read_bytes()).hexdigest(),
                  'installer_sha256':hashlib.sha256((ROOT/'tools/apply_gateway_patch.py').read_bytes()).hexdigest(),
                  'build_target':'x86_64-unknown-linux-gnu',
                  'build_environment_policy':'allowlist-v1-fresh-cargo-home-and-target',
                  'wire_profile':'normalized-text-v1','toolchain':'1.98.0','build_features':['jemalloc','mimalloc','crypto-aws-lc'],
                  'binary_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'suite':accept.suite_binding()}
            m.write_text(json.dumps(info)); digest=hashlib.sha256(m.read_bytes()).hexdigest()
            with patch.dict(os.environ,{},clear=True):
                with self.assertRaisesRegex(ValueError,'REFERENCE'): accept.verify_build(exe,m)
            with patch.dict(os.environ,{'BUILD_MANIFEST_SHA256':digest}):
                accept.verify_build(exe,m)
                with patch.object(accept,'suite_binding',return_value={'changed':True}):
                    with self.assertRaises(ValueError): accept.verify_build(exe,m)
                m.write_text(json.dumps(dict(info,binary_sha256='0'*64)))
                with self.assertRaisesRegex(ValueError,'REFERENCE'): accept.verify_build(exe,m)


@unittest.skipUnless(sys.platform=='linux','Linux process attribution contract')
class ListenerIdentity(unittest.TestCase):
    def test_other_process_on_port_is_not_gateway(self):
        code='import socket,sys; s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(); print(s.getsockname()[1],flush=True); sys.stdin.read()'
        proc = subprocess.Popen([sys.executable,'-c',code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        try:
            port=int(proc.stdout.readline())
            wait_listener(proc,Path(sys.executable),port,1)
            impostor=Mock(pid=os.getpid()); impostor.poll.return_value=None
            self.assertFalse(listener_owned(impostor,Path(sys.executable),port))
        finally:
            proc.communicate(timeout=5)


class ContextContract(unittest.TestCase):
    def headers(self, **changes):
        data={'x-ag-original-path':'/v1/chat/completions','x-ag-original-media-type':'application/json',
              'x-ag-effective-stream':'false','x-ag-requested-model':'fixture'}
        data.update(changes); m=Message()
        for k,v in data.items(): m[k]=v
        return m

    def test_absent_duplicate_and_invalid_context_never_defaults(self):
        for k in HEADER_EXPRESSIONS:
            m=self.headers(); del m[k]; self.assertEqual(decide(m)[:2],(False,'CONTEXT_UNAVAILABLE'))
            m=self.headers(); m[k]=m[k]; self.assertEqual(decide(m)[:2],(False,'CONTEXT_UNAVAILABLE'))
        m=self.headers(**{'x-ag-effective-stream':'0'}); self.assertFalse(decide(m)[0])

    def test_positive_and_deterministic_denials(self):
        self.assertTrue(decide(self.headers())[0])
        for field,value,reason in [('x-ag-effective-stream','true','STREAMING_DENIED'),('x-ag-requested-model','other','MODEL_DENIED'),
                                   ('x-ag-original-media-type','text/plain','MEDIA_TYPE_DENIED'),('x-ag-original-path','/v1/files','ENDPOINT_DENIED')]:
            self.assertEqual(decide(self.headers(**{field:value}))[1],reason)

    def test_case_alias_cannot_override_reserved_header(self):
        with self.assertRaises(ValueError): validate_config(dict(HEADER_EXPRESSIONS, **{'X-Ag-Effective-Stream':'"false"'}))

    def test_original_model_profile_rejects_model_override_and_transformations(self):
        from tools.gateway_probe import gateway_config
        route=gateway_config(1234,4321)['binds'][0]['listeners'][0]['routes'][0]
        for phase in ('request','response'):
            route['policies']['ai']['promptGuard'][phase][0]['webhook']['headers']=dict(HEADER_EXPRESSIONS)
        with self.assertRaisesRegex(ValueError,'CONTEXT_ROUTE_UNVERIFIED'): validate_route(route)
        route['backends'][0]['ai']['provider']['openAI']={}
        validate_route(route)
        route['policies']['transformation']={}
        with self.assertRaises(ValueError): validate_route(route)
