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

Final formatting passes. Remaining build/test results pending completion; update before submission.

## Independent failure and remaining boundaries

Integration & Soak run https://github.com/loviswaternakamoto/x0x/actions/runs/39223803733: actual job 117965106744 log fails `non_creator_admin_invite_e2e_converges_through_real_daemons` at tests/named_group_join_metadata_event.rs:897, `invite missing base member snapshot; cannot derive creator provenance`. Soak Test was cancelled. This patch does not repair invitation provenance or declare all CI green.

Upstream priority checked: saorsa-labs/x0x #622's latest dirvine comment redirects remaining egress work to #504 (open); #505 is field-accepted/closed. No mesh measurement or runtime adoption claimed here.
