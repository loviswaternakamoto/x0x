# Direct transport experiment

This harness measures x0x `NetworkNode::send_direct` / `recv_direct` over the
unchanged pinned ant-quic transport, with signed x0x announcement payloads.
It does not measure WebRTC, ANT chunks, gossip propagation, the Agent DM
authorization API, WAN/NAT traversal, DAO execution or production capacity.

Build the release example with the existing pinned Nix shell, Rust 1.95.0,
Cargo.lock and `--features bnrose-shadow --example bnrose_delivery --locked`.
`run-nixos.sh` is the bounded Hostinger validation launcher; its binary and
receipt paths are explicit. It requires systemd and a Linux host capable of
creating a private network namespace. It fails if a build is running, the
receipt name exists, or isolation admission fails. It never changes firewall
rules, production daemons or public peer membership.

Two independent ephemeral peer pairs each send three bursts of 128 signed
announcements. The sender has at most 8 or 64 send calls in flight. Each call
has a 500 ms experimental deadline; each burst gets a 500 ms settle interval.
The churn arm withdraws one receiver for the middle burst, then rebuilds it
with the same ephemeral transport key and a new port before the final burst.
The other pair does not withdraw. These are bounded bursts, not a sustained
offered-rate or saturation experiment. Withdrawal is between bursts, not a
random mid-packet fault. No application retransmission is added; loss during
withdrawal must remain visible.

Application delivery is counted only after ML-DSA verification and local
machine/agent/freshness checks. The shadow arm uses `ShadowObserver::observe`,
which performs the same baseline verification before BNRoSe admission. Its
Replay verdict is observational and does not revoke verified application
delivery. Restarting the receiver resets only this ephemeral observer state.
Each pair then sends a modified signed payload and requires Signature refusal.
Transport allowlists are local and limited to that pair. No user keys, wallet,
DAO decision, delegation or production identity is used or changed.

Raw receipts distinguish send completion, received bytes and verified delivery,
with message IDs and monotonic timestamps from the same process. They retain
each phase's transport statistics; connection-generation counters must not be
summed blindly across restart. No classical verification substitute or signature
cache is used. Runtime negotiated key-exchange identifiers are not exposed by
this harness; the transport configuration is unchanged, not independently
attested by these metrics.

Run baseline and shadow in alternating order, at both windows and with/without
withdrawal. Keep failed and preliminary executions separate from the fixed
measurement matrix. On a shared VPS, report run ranges and missing messages
alongside latency quantiles, and never convert this result into a global user
capacity or a WebRTC–ANT result.
