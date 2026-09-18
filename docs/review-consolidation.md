# PR #7 / #8 consolidation — 2026-09-18

PR #7 and #8 were duplicate implementations of the same P0 work, not stacked
changes. #7 is closed without merge or branch deletion. #8 is the only maintained
implementation. Historical #7 builds and reviews are retained, not relabelled as
fixed or passed on that old branch.

| Review concern | Canonical implementation and executable evidence |
|---|---|
| Generic failures counted as valid malformed-action rejection | gateway_acceptance requires exact 503 + per-call sanitized AG_WIRE_INVALID_RESPONSE log classification; tests reject 400/401/502 and generic errors. |
| Unattributed released port | process_identity verifies child executable and LISTEN socket inode before readiness and before/after each call; a different-process listener test fails attribution. |
| Shrinking fixture set validates itself | fixed 84 phase identities, suite digest, raw fixture/runner/helper hashes bound in producer manifest; shrink and substitution tests. |
| Manifest hashes treated as authentication | separate build/consumer jobs, immutable artifact ID and job-output reference; no release attestation or deployment approval claimed. |
| Partial patch writes | stage all files, rollback caught replace failures, actual filesystem assertions for each output; crash/rollback-I/O failure requires disposable checkout replacement. |
| Upstream tree drift | exact Git root/HEAD/clean worktree before patch; build only allows reviewed two-file diff and verifies patch hashes/default features. |
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

13 registered scenarios cover original path/media/model/stream observation,
OpenAI's omitted-stream default via an explicit CEL expression (not a missing
header fallback), forged client headers being overwritten, true streaming,
unapproved models, and four individually missing/failed CEL mappings. A verified
body-only waveform does not establish original input coverage, identity, arbitrary
provider behavior, all endpoint ingress, or complete deadline/audit guarantees.

Local stock Gateway context observations are diagnostic development evidence.
Only the exact new CI build's native/Compose artifacts establish its scoped
results. Full P0, ASR/FPR, and release approval remain unevaluated/unapproved.

## CI toolchain pin correction

Run 35301210454 failed before the Gateway compilation: the minor channel `1.98`
installed Rust 1.98.1 while the build gate required 1.98.0. The workflow, build
entrypoint, and manifest now all require the full `1.98.0` pin. The version check
was not relaxed; the failed run remains evidence of a correctly rejected mismatch.
