# Security audit remediation — 2026-10-19

## Scope and revisions

Base: `cfb097504cfe2d2eaf3cdc6176b02585142450aa` on loviswaternakamoto/x0x main. Isolated branch: `codex/security-audit-2026-10-19`.
Original Security Audit: https://github.com/loviswaternakamoto/x0x/actions/runs/39189161103 (Cargo Audit job 117857912778). Read the job log: seven vulnerabilities, plus five advisory warnings.

Changes: Cargo.lock rustls 0.23.45 → 0.23.46; Cargo.toml zip 2.0 → 9.0, locked at 9.0.0. Retain ZIP default features to avoid silently dropping supported compression/encryption formats. The ZIP major upgrade necessarily changes its compression/encryption dependency subtree. No transport, gossip, identity, peer authority, TLS policy or provider settings change. ZIP 9 makes `ZipFile::name` fallible; explicitly propagate decoding errors as ExtractionError before applying the existing exact-basename rule. New tests exercise deflate, privileged attributes and external-target symlink rejection.

## Dependency and reachability analysis

Measured with `cargo +1.95.0 tree --locked -i rustls -e features` and the equivalent zip command; repeat with `--all-features` on the candidate.

- x0x → zip 2.4.2, directly. Production use is only `src/upgrade/apply.rs::extract_from_zip`, called by `extract_binary_from_archive`. Tests additionally use ZipWriter. Default features include deflate, deflate64, bzip2, zstd, lzma and aes-crypto; these are retained.
- x0x → reqwest 0.12.28 → hyper-rustls 0.27.10 / tokio-rustls 0.26.5 → rustls 0.23.45.
- x0x → ant-quic 0.27.54 → rustls, rustls-post-quantum 0.2.4 and rustls-platform-verifier 0.6.2. saorsa-gossip 0.5.86 coordinator/transport/runtime also reach ant-quic and its reqwest HTTP client. The transport pins remain exact and unchanged.
- rustls features: aws-lc-rs/aws_lc_rs, default, log/logging, prefer-post-quantum, ring, std, tls12. No Brotli, including with all x0x features enabled.

| Advisory | Affected operation and x0x assessment |
| --- | --- |
| [RUSTSEC-2026-0346](https://rustsec.org/advisories/RUSTSEC-2026-0346.html) | Debug formatting TLS client session values in a custom ClientSessionStore. No custom store implementation or session-value Debug logging found in x0x, ant-quic 0.27.54 or reqwest 0.12.28. Built-in cache Debug is excluded by the advisory. No affected call site established. |
| [RUSTSEC-2026-0347](https://rustsec.org/advisories/RUSTSEC-2026-0347.html) | ECH enabled, rejected config, and buffered application data before handshake completion. No EchMode/explicit ECH setup found in x0x, ant-quic or reqwest sources. No affected configuration established; QUIC does not use the ClientConnection writer/write_tls path described by the advisory. |
| [RUSTSEC-2026-0348](https://rustsec.org/advisories/RUSTSEC-2026-0348.html) | Built-in Brotli certificate decompressor. Feature absent from default and all-features graphs, so this decompressor is not compiled. |
| [RUSTSEC-2026-0349](https://rustsec.org/advisories/RUSTSEC-2026-0349.html) | Unauthenticated ServerHello poisons the cached key-exchange hint. Treat as potentially reachable through ordinary HTTPS clients and configurations permitting classical groups; no practical exploit reproduced. ant-quic `src/crypto/pqc/pqc_crypto_provider.rs::create_pqc_provider` replaces groups with MLKEM768/MLKEM1024 when ML-KEM is enabled. However `src/crypto/rustls.rs::configured_provider_with_pqc` has an existing error fallback to `configured_provider`, which uses AWS-LC defaults. Thus do not infer universal immunity from PQ intent or change provider policy as part of this patch. Upgrade the shared rustls implementation. |
| [RUSTSEC-2026-0367](https://rustsec.org/advisories/RUSTSEC-2026-0367.html) | Bulk extraction preserving privileged archive modes. x0x uses by_index + is_file + io::copy into a caller-selected fixed output path and explicitly sets Unix mode 0755; it never calls ZipArchive::extract or the stream extraction API. Advisory-specific path is not reached. |
| [RUSTSEC-2026-0368](https://rustsec.org/advisories/RUSTSEC-2026-0368.html) | Bulk extraction materializes external-target symlinks. No bulk extractor or symlink creation call in the x0x ZIP path. ZIP 9 is_file excludes symlinks; new regression ensures a matching link is rejected and the external target unchanged. |
| [RUSTSEC-2026-0369](https://rustsec.org/advisories/RUSTSEC-2026-0369.html) | Bulk/stream extraction chmod through archive-created symlinks. Neither API is called by x0x. Its fixed-path copy and explicit chmod do not materialize archive links. This analysis does not claim immunity to pre-existing hostile filesystem state. |

## Validation

Fresh `cargo +1.95.0 audit --json` exits 0: zero vulnerabilities (database commit `999ec89d5d3f10f20be14750ec8c2d8b44e0ac9b`, 1338 advisories). Full receipt: `proofs/security-audit-2026-10-19/cargo-audit.json`. Five existing warnings remain: audiopus_sys RUSTSEC-2026-0150, paste RUSTSEC-2024-0436, unsafe-libyaml RUSTSEC-2024-0449 (unmaintained); lru RUSTSEC-2026-0253 (unsound); yoke-derive 0.8.3 (yanked). No advisory ignores or feature removals added.

Validation on code revision `68531024faa4f991326f4bc135e89b4a7c96fe7f`:

- `cargo +1.95.0 build --locked --bins`: **exit 0**, Linux x86_64, all binary targets linked (36m 06s cold local build). Nothing executed or deployed from these binaries.
- GitHub checks on this revision: Cargo Audit, Clippy Lint and Build linux-x64-gnu **success**; broader test jobs were still in progress at the last read. These results are revision-bound, not a declaration that every check is green. The PR remains draft.
- Full local formatting passed before the test-expectation correction; `rustfmt +1.95.0 --edition 2021 src/upgrade/apply.rs` ran after that correction. Hosted Format Check also runs on the PR.
- First reviewed inert regression run (`cargo +1.95.0 test --locked --lib upgrade::apply::tests::test_extract -- --nocapture`): **14 tests, 13 passed, 1 failed**. The new permissions test incorrectly expected the patched ZIP reader's `unix_mode()` to expose privileged bits (`left: 511`, `right: 3583`). ZIP 9's `format/functions.rs::get_unix_mode` already strips those bits. Commit `6853102` corrects the expected sanitized metadata to 0777 and retains the deflated output/content and final 0755 mode assertions. Production code is unchanged by that correction.
- Corrected regression rerun was launched and reached x0x compilation, but its result is **UNVERIFIED**: WSL's service stopped responding to new calls with `Wsl/Service/0x8007274c` (connection attempt timed out). Do not infer success from the absence of a final log line. The first run's external-target ZIP symlink test passed. No environment reset, service restart or disruption of other agents was attempted.
- Standard isolated launcher: **exit 1**, `sudo: interactive authentication is required`. The direct Cargo selector above was reviewed as inert: local archive files only, no peers, network or daemon startup. It does not replace isolated full-suite acceptance.
- Initial all-features Clippy failed in existing audiopus_sys 0.2.2 because installed CMake 4 removed old policy compatibility; an environment-only `CMAKE_POLICY_VERSION_MINIMUM=3.5` retry was queued, then cancelled after the equivalent hosted check passed. Local workspace checks were stopped after recording ZIP 9's changed name API and later after hosted all-targets Clippy passed, to avoid redundant compilation. **No completed local workspace-check pass is claimed.**
- Native Windows toolchain startup also failed while downloading a declared Apple cross-target (`rust-std-aarch64-apple-darwin`, file rename os error 2); validation used the installed Linux 1.95.0 toolchain instead.

The code revision above is unchanged by a later receipt-only commit. Source/manifest/lock bytes must be compared when attributing earlier CI to a newer receipt-only head. The original independent invitation failure and skipped PR timing/soak jobs remain outside this remediation's acceptance claim.

## Independent failure and remaining boundaries

Integration & Soak run https://github.com/loviswaternakamoto/x0x/actions/runs/39223803733: actual job 117965106744 log fails `non_creator_admin_invite_e2e_converges_through_real_daemons` at tests/named_group_join_metadata_event.rs:897, `invite missing base member snapshot; cannot derive creator provenance`. Soak Test was cancelled. This patch does not repair invitation provenance or declare all CI green.

Upstream priority checked: saorsa-labs/x0x #622's latest dirvine comment redirects remaining egress work to #504 (open); #505 is field-accepted/closed. No mesh measurement or runtime adoption claimed here.
