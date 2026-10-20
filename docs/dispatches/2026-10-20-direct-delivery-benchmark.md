# Direct x0x transport: native NixOS load and withdrawal experiment

Separate descendant of PR #4 head `85633f6a6dfea44e62a0cad778aa429275fc4604`.
PR #4 remains unmerged. Only the example, example registration and validation
instructions were added; production transport, shadow policy and Cargo.lock
are unchanged.

On Hostinger NixOS 26.05, 24 isolated processes covered baseline/shadow,
8/64 in-flight sends, steady/receiver withdrawal, three repeats. Two ephemeral
peer pairs per process each sent three bursts of 128 signed announcements.
The exact methodology and limitations are in
[`scripts/dev/bnrose-delivery/README.md`](../../scripts/dev/bnrose-delivery/README.md).

There were 18,432 attempts: 16,896 verified deliveries and 1,536 failed sends
while a receiver was deliberately offline. No online messages were missing.
All 12 recovery bursts delivered 128/128 messages after reconnect, and all 48
network-delivered tampered-signature controls were refused.

Native release build, `cargo fmt --all -- --check` and native release Clippy
for `--features bnrose-shadow --example bnrose_delivery -- -D warnings` passed.
The full all-target/all-feature CI suite was not rerun for this benchmark.

| In-flight bound | Condition | Baseline median phase p50 | Shadow median phase p50 |
| --- | --- | ---: | ---: |
| 8 | steady | 17.124 ms | 16.767 ms |
| 8 | withdrawal/rejoin | 12.277 ms | 13.613 ms |
| 64 | steady | 21.135 ms | 20.400 ms |
| 64 | withdrawal/rejoin | 21.517 ms | 19.622 ms |

These are medians of per-run phase medians, excluding the deliberately offline
phase; they are not pooled message quantiles. Repeat-level changes vary widely
in both directions. No speed improvement is established.

An important observation: 5,899 of 8,448 shadow-verified messages (69.83%)
were labelled Replay by the monotonic diagnostic watermark because independent
streams delivered them out of order. There were zero duplicate application IDs.
Only 2,549 entered BNRoSe core admission. All signatures were checked;
the diagnostic Replay verdict did not suppress verified application delivery.
This measures the existing observer under stream reordering, not full core
admission on every delivered message. Turning that diagnostic verdict into a
delivery gate would discard valid messages and is not justified by this work.

These results exercise x0x NetworkNode direct streams over ant-quic on private
loopback sockets. They do not exercise WebRTC–ANT retrieval, Agent-level DM
authorization, gossip, WAN or public mesh delivery. The browser ANT chunk path
has no matching BNRoSe observation hook or controlled storage-node churn harness.
The integrated browser-path comparison therefore remains unexecuted.

ML-DSA verification remains `src/bnrose_shadow.rs::verify_baseline` calling
`IdentityAnnouncementV3::verify`; `ShadowObserver::observe` preserves that call
before its diagnostic watermark. Each receiver selects its own exact
machine/agent scope and transport allowlist. No DAO authority, user identity,
wallet, delegation or production service is changed or exercised.

Raw paired send/delivery timestamps, transport snapshots, isolation receipts,
build provenance and analysis are published in the BNR
`codex/invitation-validation-receipts` branch under
`docs/receipts/bnrose-delivery-20261020/`. The companion dispatch is
`docs/dispatches/2026-10-20-bnrose-direct-delivery-nixos.md`.
PR #3 audit remediation, PR #5 invitation validation and Oracle capacity remain
separate from this experiment.
