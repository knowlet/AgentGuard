# PR #7 / #8 consolidation — 2026-09-18

PR #7 and #8 were duplicate implementations of the same P0 work, not stacked
changes. #7 is closed without merge or branch deletion. Historical #7 builds and
reviews are retained, not relabelled as fixed or passed on that old branch.

## State after the #8 merge

#8 was squash-merged into `develop` as `27046ff` ("feat(p0): harden Gateway wire
parsing and verify dual-phase context (#8)"). Its content is preserved exactly:
files that only #8 touched, such as `tools/context_probe.py`,
`docs/adr-001-strict-gateway-wire.md` and the strict-wire patch, are byte-identical
between `develop` and the branch that carried #8.

The P0 deadline slice (PR #9) was stacked on #8 and is now retargeted to
`develop`. Because #8 landed as a **squash**, a branch that still carries #8's
original commits has no shared history with `develop` beyond the pre-#8 base, so
GitHub's three-dot diff re-includes #8's files next to the new slice. That is a
display artifact of the squash, not a second copy of the work: the three files
the deadline slice also edits (`tools/gateway_acceptance.py`, `README.md`,
`.github/workflows/p0-patched.yml`) are the only ones whose content differs from
`develop`, and each difference is the slice's own addition.

| Review concern | Canonical implementation and executable evidence |
|---|---|
| Generic failures counted as valid malformed-action rejection | gateway_acceptance requires exact 503 + per-call sanitized AG_WIRE_INVALID_RESPONSE log classification; tests reject 400/401/502 and generic errors. |
| Unattributed released port | process_identity verifies child executable and LISTEN socket inode before readiness and before/after each call; a different-process listener test fails attribution. |
| Shrinking fixture set validates itself | fixed 84 phase identities, suite digest, raw fixture/runner/helper hashes bound in producer manifest; shrink and substitution tests. |
| Manifest hashes treated as authentication | separate build/consumer jobs, immutable artifact ID and job-output reference; no release attestation or deployment approval claimed. |
| Partial patch writes | stage all files, rollback caught replace failures, actual filesystem assertions for each output; crash/rollback-I/O failure requires disposable checkout replacement. |
| Upstream tree drift | exact Git root/HEAD/clean worktree before patch; build recomputes patched bytes from pinned Git objects, permits only the reviewed two-file diff, rejects untracked/ignored inputs, and verifies actual defaults. |
| Source-text tests instead of behavior | execute patch generator and report path; inspect written bytes/JSON and CLI exit status. |
| Toolchain/default features | one build entrypoint verifies actual defaults, command argv/environment, and rustc version; fake compiler tests exercise the entrypoint. |
| Faults without recovery | HTTP status/non-JSON/disconnect/truncation/10s timeout, each followed by allowed request, separate from ASR/FPR. |
| Ambiguous case increments | existing 22 fixtures/42 phases + 21 strict fixtures/42 phases = 84; the 10 array phases are included, not extra. |

## G0-CONTEXT slice

The new route preflight accepts only a closed, one-backend OpenAI text route with
exact reserved-header CEL expressions, failClosed, and no transformations or
provider model override. No route activation service exists yet. A rejected
configuration is launched only by the fault-injection runner to independently
verify runtime missing-context denial, never as a production fallback.

37 registered scenarios now exercise **both request and response**: five legitimate/
policy controls and 32 missing/failed-mapping cases (2 phases × 4 headers ×
2 failure types × with/without forged client headers). Response denials require
request allow, one upstream execution, response hook observation, and no client
marker. Positive controls preserve the payload and inspect both contexts.

The old request-only probe masked a real integration defect: upstream response
webhook evaluation receives no `llmRequest`. Both phases now use the original
buffered `json(request.body)` for model/stream. Missing/invalid body does not mean
`stream=false`: only a successfully parsed object lacking the stream key gets
that documented protocol default. Non-boolean stream values produce `invalid`.
The narrow profile still forbids transformations/model overrides; raw body is
retained in bounded request-snapshot memory, not emitted into these decision logs.

The fixture configuration also previously shared one mutable webhook object
between phases. The new builder deliberately separates them, with a regression
ensuring a response-only mapping fault leaves request mappings intact.

Per-case configs/logs and distinct phase decisions are preserved. A finite
context suite does not establish arbitrary original-field coverage, identity,
all endpoints, or complete deadline/audit guarantees.

Local stock Gateway context observations are diagnostic development evidence.
Only the exact new CI build's native/Compose artifacts establish its scoped
results. Full P0, ASR/FPR, and release approval remain unevaluated/unapproved.

## CI toolchain pin correction

Run 35301210454 failed before the Gateway compilation: the minor channel `1.98`
installed Rust 1.98.1 while the build gate required 1.98.0. The workflow, build
entrypoint, and manifest now all require the full `1.98.0` pin. The version check
was not relaxed; the failed run remains evidence of a correctly rejected mismatch.

## Second review hardening

- The build manifest cannot attest its own modified webhook: expected bytes are
  regenerated from the pinned upstream Git object and local exact patch, then
  compared with both worktree and manifest, before and after compilation.
- Cargo uses an allowlisted environment, fresh CARGO_HOME/target directory, fixed
  target/flags/toolchain. All inherited Cargo/Rust/native-compiler overrides and
  credentials are absent. Runner PATH/compiler/linker/kernel remain trust roots;
  this is not a claim of reproducible release bytes or hostile-host resistance.
- Atomic writes validate every existing ancestor before writing, then traverse
  and replace through O_NOFOLLOW directory handles. Symlink and I/O-failure tests
  use actual filesystem objects. Concurrent root/same-UID directory renames and
  crash atomicity remain outside the private-workspace contract.
- Every active workflow script explicitly sets `-euo pipefail`. Tests execute
  the actual saved Python-test run block with a failing executable on PATH;
  comments or an unrelated bash command cannot make that regression pass.

New source changes require a fresh producer build and native/Compose acceptance.
Earlier successful run IDs remain historical, not evidence for this new head.

## Third review hardening

| Review concern | Canonical implementation and executable evidence |
|---|---|
| `assume-unchanged`/`skip-worktree` hides worktree edits from `git diff` and `git status` | The installer and the build gate reject any non-`H` index tag before reading or compiling; regressions first assert that `git status --porcelain` stays silent for the modified input, then assert both gates refuse and no binary is published. |
| A suite that defines its own expected identities | `context_probe` gates on a frozen 37-identity registry derived from declared constants, not from `cases()`, and builds its fixture mappings from that frozen header-to-CEL map. Shrinking the generator raises `CONTEXT_SUITE_CHANGED`; renaming a header or editing only its CEL value raises `CONTEXT_MAPPING_CHANGED` instead of passing. |
| Test oracle that depends on `/proc` and a symlink-free path | The rollback failure injection compares directory identity by `os.fstat` dev/inode against `os.stat(target.parent)`, so it works under a symlinked TMPDIR and on non-Linux hosts while still failing if the injected error never fires. |

The index-flag rejection covers the two documented stat-cache flags and fails closed on
any other non-normal tag. It does not enumerate every way a writer with checkout access
could alter inputs; the runner, its compiler/linker and the checked-out tree remain the
trust root, exactly as for the rest of this build path.
